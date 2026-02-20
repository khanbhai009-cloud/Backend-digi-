require("dotenv").config({ path: require("path").resolve(__dirname, "../.env") });
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { Cashfree } = require("cashfree-pg");
const { db, admin, sendFCM, getUserFCMToken } = require("../lib/firebase");
const { authenticateUser } = require("../lib/middleware");

const app = express();
app.use(cors({ origin: "*" }));

// Cashfree webhook needs raw body for signature verification
app.use("/api/payment/webhook", express.raw({ type: "application/json" }));
app.use(express.json());

// ─────────────────────────────────────────
// CASHFREE INITIALIZATION
// ─────────────────────────────────────────

Cashfree.XClientId = process.env.CASHFREE_APP_ID;
Cashfree.XClientSecret = process.env.CASHFREE_SECRET_KEY;
Cashfree.XEnvironment =
  process.env.CASHFREE_ENV === "production"
    ? Cashfree.Environment.PRODUCTION
    : Cashfree.Environment.SANDBOX;

// ─────────────────────────────────────────
// POST /api/payment/create
// ─────────────────────────────────────────

app.post("/api/payment/create", authenticateUser, async (req, res) => {
  try {
    const { productId } = req.body;

    if (!productId) {
      return res.status(400).json({ error: "productId is required" });
    }

    const [productDoc, buyerDoc] = await Promise.all([
      db.collection("products").doc(productId).get(),
      db.collection("users").doc(req.user.uid).get(),
    ]);

    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }
    if (!buyerDoc.exists) {
      return res.status(404).json({ error: "Buyer account not found" });
    }

    const product = productDoc.data();
    const buyer = buyerDoc.data();

    if (product.status !== "approved") {
      return res.status(400).json({ error: "This product is not available for purchase" });
    }

    const existingOrder = await db
      .collection("orders")
      .where("buyerId", "==", req.user.uid)
      .where("productId", "==", productId)
      .where("status", "==", "completed")
      .limit(1)
      .get();

    if (!existingOrder.empty) {
      return res.status(409).json({ error: "You have already purchased this product" });
    }

    const orderAmount = product.discountPrice || product.price;
    const orderId = "ORD_" + uuidv4().replace(/-/g, "").slice(0, 20).toUpperCase();

    const cashfreeOrderPayload = {
      order_id: orderId,
      order_amount: orderAmount,
      order_currency: "INR",
      customer_details: {
        customer_id: req.user.uid,
        customer_email: buyer.email,
        customer_phone: buyer.phone || "9999999999",
        customer_name: buyer.fullName,
      },
      order_meta: {
        return_url:
          `${process.env.FRONTEND_URL}/user.html?payment=success&product=${productId}&order=${orderId}`,
        notify_url: `${process.env.BACKEND_URL}/api/payment/webhook`,
      },
    };

    let cashfreeOrder;
    try {
      const response = await Cashfree.PGCreateOrder("2023-08-01", cashfreeOrderPayload);
      cashfreeOrder = response.data;
    } catch (cfErr) {
      const errMsg = cfErr.response?.data?.message || cfErr.message;
      console.error(`[Payment] Cashfree order creation failed: ${errMsg}`);
      return res.status(502).json({ error: `Payment gateway error: ${errMsg}` });
    }

    await db.collection("orders").doc(orderId).set({
      orderId,
      buyerId: req.user.uid,
      sellerId: product.sellerId,
      productId,
      amount: orderAmount,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`[Payment] Order ${orderId} created for product ${productId} by ${req.user.uid}`);

    return res.status(201).json({
      paymentSessionId: cashfreeOrder.payment_session_id,
      orderId,
    });
  } catch (err) {
    console.error(`[Payment/Create] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to create payment order" });
  }
});

// ─────────────────────────────────────────
// POST /api/payment/webhook
// ─────────────────────────────────────────

app.post("/api/payment/webhook", async (req, res) => {
  // Always return 200 so Cashfree doesn't retry endlessly on our logic errors
  try {
    const rawBody = Buffer.isBuffer(req.body) ? req.body.toString("utf8") : JSON.stringify(req.body);
    const signature = req.headers["x-webhook-signature"];
    const timestamp = req.headers["x-webhook-timestamp"];

    if (!signature || !timestamp) {
      console.error("[Webhook] Missing signature or timestamp headers");
      return res.status(200).json({ status: "signature_missing" });
    }

    // Cashfree HMAC-SHA256 signature verification
    const signedPayload = timestamp + rawBody;
    const expectedSignature = crypto
      .createHmac("sha256", process.env.CASHFREE_SECRET_KEY)
      .update(signedPayload)
      .digest("base64");

    if (expectedSignature !== signature) {
      console.error("[Webhook] Invalid signature — possible spoofed request");
      return res.status(200).json({ status: "invalid_signature" });
    }

    const event = JSON.parse(rawBody);
    const paymentStatus = event?.data?.payment?.payment_status;
    const orderId = event?.data?.order?.order_id;

    console.log(`[Webhook] Event received for order ${orderId}, status: ${paymentStatus}`);

    if (!orderId) {
      console.error("[Webhook] Missing orderId in payload");
      return res.status(200).json({ status: "missing_order_id" });
    }

    const orderRef = db.collection("orders").doc(orderId);
    const orderDoc = await orderRef.get();

    if (!orderDoc.exists) {
      console.error(`[Webhook] Order ${orderId} not found in Firestore`);
      return res.status(200).json({ status: "order_not_found" });
    }

    const order = orderDoc.data();

    if (paymentStatus === "SUCCESS") {
      // Prevent double processing
      if (order.status === "completed") {
        console.log(`[Webhook] Order ${orderId} already completed — skipping`);
        return res.status(200).json({ status: "already_completed" });
      }

      const configDoc = await db.collection("config").doc("app_config").get();
      const commissionRate = configDoc.exists ? configDoc.data().commissionRate || 10 : 10;
      const amount = order.amount;
      const platformFee = amount * (commissionRate / 100);
      const sellerEarning = amount - platformFee;

      // Atomic batch write
      const batch = db.batch();

      batch.update(orderRef, {
        status: "completed",
        platformFee,
        sellerEarning,
        completedAt: admin.firestore.FieldValue.serverTimestamp(),
      });

      const sellerRef = db.collection("users").doc(order.sellerId);
      batch.update(sellerRef, {
        walletBalance: admin.firestore.FieldValue.increment(sellerEarning),
        totalEarnings: admin.firestore.FieldValue.increment(sellerEarning),
      });

      const productRef = db.collection("products").doc(order.productId);
      batch.update(productRef, {
        sales: admin.firestore.FieldValue.increment(1),
      });

      const buyerRef = db.collection("users").doc(order.buyerId);
      batch.update(buyerRef, {
        purchases: admin.firestore.FieldValue.arrayUnion(order.productId),
      });

      await batch.commit();
      console.log(`[Webhook] Order ${orderId} completed. Seller earns ₹${sellerEarning}, platform fee ₹${platformFee}`);

      // FCM to seller
      const sellerToken = await getUserFCMToken(order.sellerId);
      await sendFCM(
        sellerToken,
        "🎉 New Sale!",
        `₹${sellerEarning} added to your wallet`,
        { type: "payment", orderId }
      );

      // FCM to buyer
      const buyerToken = await getUserFCMToken(order.buyerId);
      await sendFCM(
        buyerToken,
        "✅ Purchase Confirmed!",
        "Your download is ready. Tap to download!",
        { type: "download", productId: order.productId }
      );
    } else if (paymentStatus === "FAILED") {
      if (order.status !== "completed") {
        await orderRef.update({
          status: "failed",
          failedAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        console.log(`[Webhook] Order ${orderId} marked as failed`);

        const buyerToken = await getUserFCMToken(order.buyerId);
        await sendFCM(
          buyerToken,
          "❌ Payment Failed",
          "Something went wrong. Please try again."
        );
      }
    } else {
      console.log(`[Webhook] Unhandled payment status "${paymentStatus}" for order ${orderId}`);
    }

    return res.status(200).json({ status: "ok" });
  } catch (err) {
    console.error(`[Webhook] Unexpected error: ${err.message}`, err.stack);
    return res.status(200).json({ status: "error", message: err.message });
  }
});

// ─────────────────────────────────────────
// GET /api/payment/status/:orderId
// ─────────────────────────────────────────

app.get("/api/payment/status/:orderId", authenticateUser, async (req, res) => {
  try {
    const { orderId } = req.params;
    const orderDoc = await db.collection("orders").doc(orderId).get();

    if (!orderDoc.exists) {
      return res.status(404).json({ error: "Order not found" });
    }

    const order = orderDoc.data();

    if (order.buyerId !== req.user.uid) {
      return res.status(403).json({ error: "Access denied to this order" });
    }

    return res.json({ status: order.status, productId: order.productId });
  } catch (err) {
    console.error(`[Payment/Status] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch payment status" });
  }
});

// ─────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error(`[Payment UnhandledError] ${err.message}`, err.stack);
  return res.status(500).json({ error: "An unexpected error occurred" });
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`[Payment Server] Cashfree Payment API running on port ${PORT}`);
});

module.exports = app;
