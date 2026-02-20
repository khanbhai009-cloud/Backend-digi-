require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");
const { db, admin, sendFCM, sendFCMMulticast, getUserFCMToken } = require("../lib/firebase");
const { authenticateUser, authenticateAdmin } = require("../lib/middleware");

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

// ─────────────────────────────────────────
// ENCRYPTION HELPERS
// ─────────────────────────────────────────

const ALGORITHM = "aes-256-cbc";

function encryptLink(plainText) {
  const key = Buffer.from(process.env.ENCRYPT_KEY, "utf8").slice(0, 32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plainText, "utf8", "hex");
  encrypted += cipher.final("hex");
  return iv.toString("hex") + ":" + encrypted;
}

function decryptLink(encryptedText) {
  const [ivHex, encrypted] = encryptedText.split(":");
  const key = Buffer.from(process.env.ENCRYPT_KEY, "utf8").slice(0, 32);
  const iv = Buffer.from(ivHex, "hex");
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  let decrypted = decipher.update(encrypted, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// Strip downloadLink from product objects before sending to frontend
function sanitizeProduct(product) {
  const { downloadLink, ...safe } = product;
  return safe;
}

// ─────────────────────────────────────────
// AUTH ROUTES
// ─────────────────────────────────────────

// POST /api/auth/register
app.post("/api/auth/register", async (req, res) => {
  try {
    const { uid, email, fullName, role } = req.body;

    if (!uid || !email || !fullName || !role) {
      return res.status(400).json({ error: "Missing required fields: uid, email, fullName, role" });
    }

    if (!["buyer", "seller"].includes(role)) {
      return res.status(400).json({ error: "Role must be 'buyer' or 'seller'" });
    }

    const existingUser = await db.collection("users").doc(uid).get();
    if (existingUser.exists) {
      return res.status(409).json({ error: "User already exists" });
    }

    const userData = {
      uid,
      email,
      fullName,
      role,
      walletBalance: 0,
      totalEarnings: 0,
      wishlist: [],
      purchases: [],
      fcmToken: null,
      status: "active",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    await db.collection("users").doc(uid).set(userData);
    console.log(`[Register] New user registered: ${email} (${role})`);

    return res.status(201).json({ success: true, user: { ...userData, createdAt: new Date().toISOString() } });
  } catch (err) {
    console.error(`[Register] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to register user" });
  }
});

// GET /api/auth/user
app.get("/api/auth/user", authenticateUser, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }
    return res.json({ user: userDoc.data() });
  } catch (err) {
    console.error(`[GetUser] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});

// PATCH /api/user/profile
app.patch("/api/user/profile", authenticateUser, async (req, res) => {
  try {
    const { fullName, avatarUrl } = req.body;
    const updates = {};
    if (fullName !== undefined) updates.fullName = fullName;
    if (avatarUrl !== undefined) updates.avatarUrl = avatarUrl;

    if (Object.keys(updates).length === 0) {
      return res.status(400).json({ error: "No valid fields to update" });
    }

    await db.collection("users").doc(req.user.uid).update(updates);
    return res.json({ success: true });
  } catch (err) {
    console.error(`[UpdateProfile] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to update profile" });
  }
});

// ─────────────────────────────────────────
// PRODUCT ROUTES
// ─────────────────────────────────────────

// GET /api/products
app.get("/api/products", async (req, res) => {
  try {
    const { category, search, limit = 20, page = 1 } = req.query;
    let query = db.collection("products").where("status", "==", "approved");

    if (category) {
      query = query.where("category", "==", category);
    }

    const snapshot = await query.get();
    let products = snapshot.docs.map((doc) => sanitizeProduct({ id: doc.id, ...doc.data() }));

    if (search) {
      const searchLower = search.toLowerCase();
      products = products.filter((p) => p.title && p.title.toLowerCase().includes(searchLower));
    }

    const total = products.length;
    const start = (parseInt(page) - 1) * parseInt(limit);
    const paginated = products.slice(start, start + parseInt(limit));

    return res.json({ products: paginated, total });
  } catch (err) {
    console.error(`[GetProducts] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch products" });
  }
});

// POST /api/products/click/:id
app.post("/api/products/click/:id", async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection("products").doc(id).update({
      clicks: admin.firestore.FieldValue.increment(1),
    });
    return res.json({ success: true });
  } catch (err) {
    console.error(`[ProductClick] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to record click" });
  }
});

// GET /api/products/:id
app.get("/api/products/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const productDoc = await db.collection("products").doc(id).get();

    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    const product = sanitizeProduct({ id: productDoc.id, ...productDoc.data() });
    let sellerName = "Unknown";

    if (product.sellerId) {
      const sellerDoc = await db.collection("users").doc(product.sellerId).get();
      if (sellerDoc.exists) {
        sellerName = sellerDoc.data().fullName || "Unknown";
      }
    }

    return res.json({ product, sellerName });
  } catch (err) {
    console.error(`[GetProduct] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch product" });
  }
});

// POST /api/products/create
app.post("/api/products/create", authenticateUser, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== "seller") {
      return res.status(403).json({ error: "Only sellers can create products" });
    }

    const { title, description, price, discountPrice, category, thumbnailUrl, youtubeLink, demoLink, downloadLink } = req.body;

    if (!title || !description || !price || !category || !downloadLink) {
      return res.status(400).json({ error: "Missing required fields: title, description, price, category, downloadLink" });
    }

    const encryptedLink = encryptLink(downloadLink);

    const productData = {
      title,
      description,
      price: parseFloat(price),
      discountPrice: discountPrice ? parseFloat(discountPrice) : null,
      category,
      thumbnailUrl: thumbnailUrl || null,
      youtubeLink: youtubeLink || null,
      demoLink: demoLink || null,
      downloadLink: encryptedLink,
      sellerId: req.user.uid,
      status: "approved",
      clicks: 0,
      sales: 0,
      rating: 5.0,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    };

    const docRef = await db.collection("products").add(productData);
    console.log(`[CreateProduct] Product ${docRef.id} created by ${req.user.uid}`);

    // Notify admin via FCM
    const sellerName = userDoc.data().fullName || "A seller";
    const adminToken = await getUserFCMToken(process.env.ADMIN_EMAIL);
    if (adminToken) {
      await sendFCM(adminToken, "New Product Uploaded 📦", `${sellerName} uploaded ${title}`);
    }

    return res.status(201).json({ success: true, productId: docRef.id });
  } catch (err) {
    console.error(`[CreateProduct] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to create product" });
  }
});

// DELETE /api/products/:id
app.delete("/api/products/:id", authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const productDoc = await db.collection("products").doc(id).get();

    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    const isAdmin = req.user.email === process.env.ADMIN_EMAIL;
    const isOwner = productDoc.data().sellerId === req.user.uid;

    if (!isOwner && !isAdmin) {
      return res.status(403).json({ error: "Not authorized to delete this product" });
    }

    await db.collection("products").doc(id).delete();
    console.log(`[DeleteProduct] Product ${id} deleted by ${req.user.uid}`);

    return res.json({ success: true });
  } catch (err) {
    console.error(`[DeleteProduct] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to delete product" });
  }
});

// ─────────────────────────────────────────
// SELLER ROUTES
// ─────────────────────────────────────────

// GET /api/seller/products
app.get("/api/seller/products", authenticateUser, async (req, res) => {
  try {
    const snapshot = await db.collection("products").where("sellerId", "==", req.user.uid).get();
    const products = snapshot.docs.map((doc) => sanitizeProduct({ id: doc.id, ...doc.data() }));
    return res.json({ products });
  } catch (err) {
    console.error(`[SellerProducts] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch seller products" });
  }
});

// GET /api/seller/analytics
app.get("/api/seller/analytics", authenticateUser, async (req, res) => {
  try {
    const snapshot = await db.collection("orders").where("sellerId", "==", req.user.uid).get();

    const now = new Date();
    const last7Days = {};

    for (let i = 6; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      const dateKey = d.toISOString().split("T")[0];
      last7Days[dateKey] = { date: dateKey, amount: 0, count: 0 };
    }

    snapshot.docs.forEach((doc) => {
      const order = doc.data();
      if (order.status !== "completed") return;
      const ts = order.completedAt || order.createdAt;
      if (!ts) return;
      const date = ts.toDate ? ts.toDate() : new Date(ts);
      const dateKey = date.toISOString().split("T")[0];
      if (last7Days[dateKey]) {
        last7Days[dateKey].amount += order.sellerEarning || 0;
        last7Days[dateKey].count += 1;
      }
    });

    return res.json({ dailySales: Object.values(last7Days) });
  } catch (err) {
    console.error(`[SellerAnalytics] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch analytics" });
  }
});

// ─────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────

// GET /api/user/wishlist
app.get("/api/user/wishlist", authenticateUser, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const wishlist = userDoc.data().wishlist || [];
    if (wishlist.length === 0) {
      return res.json({ products: [] });
    }

    const productPromises = wishlist.map((pid) => db.collection("products").doc(pid).get());
    const productDocs = await Promise.all(productPromises);

    const products = productDocs
      .filter((d) => d.exists)
      .map((d) => sanitizeProduct({ id: d.id, ...d.data() }));

    return res.json({ products });
  } catch (err) {
    console.error(`[GetWishlist] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch wishlist" });
  }
});

// POST /api/user/wishlist/toggle
app.post("/api/user/wishlist/toggle", authenticateUser, async (req, res) => {
  try {
    const { productId } = req.body;
    if (!productId) {
      return res.status(400).json({ error: "productId is required" });
    }

    const userRef = db.collection("users").doc(req.user.uid);
    const userDoc = await userRef.get();

    if (!userDoc.exists) {
      return res.status(404).json({ error: "User not found" });
    }

    const wishlist = userDoc.data().wishlist || [];
    const inWishlist = wishlist.includes(productId);

    if (inWishlist) {
      await userRef.update({ wishlist: admin.firestore.FieldValue.arrayRemove(productId) });
      return res.json({ added: false });
    } else {
      await userRef.update({ wishlist: admin.firestore.FieldValue.arrayUnion(productId) });
      return res.json({ added: true });
    }
  } catch (err) {
    console.error(`[ToggleWishlist] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to update wishlist" });
  }
});

// GET /api/user/purchases
app.get("/api/user/purchases", authenticateUser, async (req, res) => {
  try {
    const snapshot = await db
      .collection("orders")
      .where("buyerId", "==", req.user.uid)
      .where("status", "==", "completed")
      .get();

    const orders = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    const enriched = await Promise.all(
      orders.map(async (order) => {
        let productTitle = "Unknown Product";
        let productThumbnail = null;
        if (order.productId) {
          const pDoc = await db.collection("products").doc(order.productId).get();
          if (pDoc.exists) {
            productTitle = pDoc.data().title || productTitle;
            productThumbnail = pDoc.data().thumbnailUrl || null;
          }
        }
        const { downloadLink, ...safeOrder } = order;
        return { ...safeOrder, productTitle, productThumbnail };
      })
    );

    return res.json({ purchases: enriched });
  } catch (err) {
    console.error(`[GetPurchases] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch purchases" });
  }
});

// ─────────────────────────────────────────
// SECURE DOWNLOAD SYSTEM
// ─────────────────────────────────────────

// GET /api/download/request/:productId
app.get("/api/download/request/:productId", authenticateUser, async (req, res) => {
  try {
    const { productId } = req.params;

    const orderSnapshot = await db
      .collection("orders")
      .where("buyerId", "==", req.user.uid)
      .where("productId", "==", productId)
      .where("status", "==", "completed")
      .limit(1)
      .get();

    if (orderSnapshot.empty) {
      return res.status(403).json({ error: "Purchase required to download this product" });
    }

    const productDoc = await db.collection("products").doc(productId).get();
    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    const encryptedLink = productDoc.data().downloadLink;
    if (!encryptedLink) {
      return res.status(500).json({ error: "Product download link is not configured" });
    }

    const decryptedLink = decryptLink(encryptedLink);

    const token = uuidv4() + "-" + crypto.randomBytes(16).toString("hex");
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

    await db.collection("download_tokens").doc(token).set({
      token,
      userId: req.user.uid,
      productId,
      decryptedLink,
      used: false,
      expiresAt,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`[Download] Token issued for user ${req.user.uid}, product ${productId}`);
    return res.json({ token });
  } catch (err) {
    console.error(`[DownloadRequest] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to generate download token" });
  }
});

// GET /api/download/:token
app.get("/api/download/:token", async (req, res) => {
  try {
    const { token } = req.params;
    const tokenRef = db.collection("download_tokens").doc(token);
    const tokenDoc = await tokenRef.get();

    if (!tokenDoc.exists) {
      return res.status(404).json({ error: "Download token not found" });
    }

    const tokenData = tokenDoc.data();

    if (tokenData.used) {
      return res.status(410).json({ error: "This download link has already been used" });
    }

    const now = new Date();
    const expiresAt = tokenData.expiresAt instanceof Date
      ? tokenData.expiresAt
      : tokenData.expiresAt.toDate
        ? tokenData.expiresAt.toDate()
        : new Date(tokenData.expiresAt);

    if (now > expiresAt) {
      return res.status(410).json({ error: "Download link has expired" });
    }

    await tokenRef.update({
      used: true,
      usedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`[Download] Token used: ${token.slice(0, 20)}... → redirecting`);
    return res.redirect(302, tokenData.decryptedLink);
  } catch (err) {
    console.error(`[Download] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to process download" });
  }
});

// ─────────────────────────────────────────
// WITHDRAWAL ROUTES
// ─────────────────────────────────────────

// POST /api/withdrawals/request
app.post("/api/withdrawals/request", authenticateUser, async (req, res) => {
  try {
    const userDoc = await db.collection("users").doc(req.user.uid).get();
    if (!userDoc.exists || userDoc.data().role !== "seller") {
      return res.status(403).json({ error: "Only sellers can request withdrawals" });
    }

    const { amount, upiId } = req.body;

    if (!amount || !upiId) {
      return res.status(400).json({ error: "amount and upiId are required" });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "amount must be a positive number" });
    }

    const walletBalance = userDoc.data().walletBalance || 0;
    if (parsedAmount > walletBalance) {
      return res.status(400).json({ error: "Insufficient wallet balance" });
    }

    await db.collection("withdrawals").add({
      sellerId: req.user.uid,
      amount: parsedAmount,
      upiId,
      status: "pending",
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    console.log(`[Withdrawal] Request by ${req.user.uid} for ₹${parsedAmount}`);
    return res.status(201).json({ success: true });
  } catch (err) {
    console.error(`[WithdrawalRequest] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to submit withdrawal request" });
  }
});

// GET /api/withdrawals/my
app.get("/api/withdrawals/my", authenticateUser, async (req, res) => {
  try {
    const snapshot = await db
      .collection("withdrawals")
      .where("sellerId", "==", req.user.uid)
      .orderBy("createdAt", "desc")
      .get();

    const withdrawals = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    return res.json({ withdrawals });
  } catch (err) {
    console.error(`[MyWithdrawals] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch withdrawals" });
  }
});

// ─────────────────────────────────────────
// NOTIFICATION ROUTES
// ─────────────────────────────────────────

// POST /api/notify/save-token
app.post("/api/notify/save-token", authenticateUser, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) {
      return res.status(400).json({ error: "token is required" });
    }

    await db.collection("fcm_tokens").doc(req.user.uid).set({
      userId: req.user.uid,
      token,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(`[SaveFCMToken] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to save notification token" });
  }
});

// POST /api/notify/broadcast
app.post("/api/notify/broadcast", authenticateAdmin, async (req, res) => {
  try {
    const { title, message } = req.body;
    if (!title || !message) {
      return res.status(400).json({ error: "title and message are required" });
    }

    const tokenSnapshot = await db.collection("fcm_tokens").get();
    const tokens = tokenSnapshot.docs.map((d) => d.data().token).filter(Boolean);

    const sent = await sendFCMMulticast(tokens, title, message);

    await db.collection("notifications").add({
      userId: null,
      title,
      body: message,
      type: "broadcast",
      isRead: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success: true, sent });
  } catch (err) {
    console.error(`[Broadcast] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to send broadcast" });
  }
});

// POST /api/notify/send-role
app.post("/api/notify/send-role", authenticateAdmin, async (req, res) => {
  try {
    const { title, message, role } = req.body;
    if (!title || !message || !role) {
      return res.status(400).json({ error: "title, message, and role are required" });
    }

    const usersSnapshot = await db.collection("users").where("role", "==", role).get();
    const userIds = usersSnapshot.docs.map((d) => d.id);

    const tokenDocs = await Promise.all(userIds.map((uid) => db.collection("fcm_tokens").doc(uid).get()));
    const tokens = tokenDocs.map((d) => (d.exists ? d.data().token : null)).filter(Boolean);

    const sent = await sendFCMMulticast(tokens, title, message);

    const batch = db.batch();
    usersSnapshot.docs.forEach((userDoc) => {
      const notifRef = db.collection("notifications").doc();
      batch.set(notifRef, {
        userId: userDoc.id,
        title,
        body: message,
        type: "role",
        isRead: false,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      });
    });
    await batch.commit();

    return res.json({ success: true, sent });
  } catch (err) {
    console.error(`[SendRole] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to send role notification" });
  }
});

// POST /api/notify/send-user
app.post("/api/notify/send-user", authenticateAdmin, async (req, res) => {
  try {
    const { title, message, userId } = req.body;
    if (!title || !message || !userId) {
      return res.status(400).json({ error: "title, message, and userId are required" });
    }

    const fcmToken = await getUserFCMToken(userId);
    if (fcmToken) {
      await sendFCM(fcmToken, title, message);
    }

    await db.collection("notifications").add({
      userId,
      title,
      body: message,
      type: "direct",
      isRead: false,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    return res.json({ success: true });
  } catch (err) {
    console.error(`[SendUser] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to send notification to user" });
  }
});

// ─────────────────────────────────────────
// PUBLIC CONFIG ROUTE
// ─────────────────────────────────────────

// GET /api/config
app.get("/api/config", async (req, res) => {
  try {
    const configDoc = await db.collection("config").doc("app_config").get();
    if (!configDoc.exists) {
      return res.status(404).json({ error: "App configuration not found" });
    }
    const { brandName, brandLogoUrl, adminEmail, adminPhone, commissionRate } = configDoc.data();
    return res.json({ brandName, brandLogoUrl, adminEmail, adminPhone, commissionRate });
  } catch (err) {
    console.error(`[GetConfig] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch app config" });
  }
});

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────

// GET /api/admin/revenue
app.get("/api/admin/revenue", authenticateAdmin, async (req, res) => {
  try {
    const ordersSnapshot = await db.collection("orders").where("status", "==", "completed").get();
    const now = new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfWeek = new Date(startOfToday);
    startOfWeek.setDate(startOfToday.getDate() - startOfToday.getDay());
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);

    let totalRevenue = 0;
    let todayRevenue = 0;
    let weekRevenue = 0;
    let monthRevenue = 0;

    ordersSnapshot.docs.forEach((doc) => {
      const order = doc.data();
      const fee = order.platformFee || 0;
      totalRevenue += fee;
      const ts = order.completedAt || order.createdAt;
      if (ts) {
        const date = ts.toDate ? ts.toDate() : new Date(ts);
        if (date >= startOfToday) todayRevenue += fee;
        if (date >= startOfWeek) weekRevenue += fee;
        if (date >= startOfMonth) monthRevenue += fee;
      }
    });

    const [usersSnap, productsSnap] = await Promise.all([
      db.collection("users").get(),
      db.collection("products").get(),
    ]);

    const allUsers = usersSnap.docs.map((d) => d.data());
    const totalUsers = allUsers.length;
    const totalSellers = allUsers.filter((u) => u.role === "seller").length;
    const totalBuyers = allUsers.filter((u) => u.role === "buyer").length;
    const totalProducts = productsSnap.size;

    return res.json({
      revenue: { total: totalRevenue, today: todayRevenue, thisWeek: weekRevenue, thisMonth: monthRevenue },
      counts: { totalUsers, totalSellers, totalBuyers, totalProducts },
    });
  } catch (err) {
    console.error(`[AdminRevenue] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch revenue data" });
  }
});

// GET /api/admin/products
app.get("/api/admin/products", authenticateAdmin, async (req, res) => {
  try {
    const { search, category } = req.query;
    let query = db.collection("products");

    if (category) {
      query = query.where("category", "==", category);
    }

    const snapshot = await query.get();
    let products = snapshot.docs.map((doc) => sanitizeProduct({ id: doc.id, ...doc.data() }));

    if (search) {
      const searchLower = search.toLowerCase();
      products = products.filter((p) => p.title && p.title.toLowerCase().includes(searchLower));
    }

    const enriched = await Promise.all(
      products.map(async (product) => {
        let sellerName = "Unknown";
        if (product.sellerId) {
          const sellerDoc = await db.collection("users").doc(product.sellerId).get();
          if (sellerDoc.exists) sellerName = sellerDoc.data().fullName || "Unknown";
        }
        return { ...product, sellerName };
      })
    );

    return res.json({ products: enriched });
  } catch (err) {
    console.error(`[AdminProducts] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch products" });
  }
});

// DELETE /api/admin/products/:id
app.delete("/api/admin/products/:id", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const productDoc = await db.collection("products").doc(id).get();

    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    const { title, sellerId } = productDoc.data();
    await db.collection("products").doc(id).delete();
    console.log(`[AdminDeleteProduct] Product ${id} deleted by admin`);

    if (sellerId) {
      const sellerToken = await getUserFCMToken(sellerId);
      await sendFCM(sellerToken, "Product Removed ⚠️", `Your product "${title}" was removed by admin`);
    }

    return res.json({ success: true });
  } catch (err) {
    console.error(`[AdminDeleteProduct] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to delete product" });
  }
});

// GET /api/admin/users
app.get("/api/admin/users", authenticateAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("users").get();
    const users = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    return res.json({ users });
  } catch (err) {
    console.error(`[AdminUsers] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch users" });
  }
});

// PATCH /api/admin/users/:id/ban
app.patch("/api/admin/users/:id/ban", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    await db.collection("users").doc(id).update({ status: "banned" });
    console.log(`[AdminBanUser] User ${id} banned`);
    return res.json({ success: true });
  } catch (err) {
    console.error(`[AdminBanUser] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to ban user" });
  }
});

// GET /api/admin/withdrawals
app.get("/api/admin/withdrawals", authenticateAdmin, async (req, res) => {
  try {
    const snapshot = await db.collection("withdrawals").orderBy("createdAt", "desc").get();
    const withdrawals = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));

    const enriched = await Promise.all(
      withdrawals.map(async (w) => {
        let sellerName = "Unknown";
        let sellerEmail = "Unknown";
        if (w.sellerId) {
          const sellerDoc = await db.collection("users").doc(w.sellerId).get();
          if (sellerDoc.exists) {
            sellerName = sellerDoc.data().fullName || sellerName;
            sellerEmail = sellerDoc.data().email || sellerEmail;
          }
        }
        return { ...w, sellerName, sellerEmail };
      })
    );

    return res.json({ withdrawals: enriched });
  } catch (err) {
    console.error(`[AdminWithdrawals] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch withdrawals" });
  }
});

// PATCH /api/admin/withdrawals/:id/pay
app.patch("/api/admin/withdrawals/:id/pay", authenticateAdmin, async (req, res) => {
  try {
    const { id } = req.params;
    const withdrawalDoc = await db.collection("withdrawals").doc(id).get();

    if (!withdrawalDoc.exists) {
      return res.status(404).json({ error: "Withdrawal not found" });
    }

    const { sellerId, amount, upiId } = withdrawalDoc.data();
    await db.collection("withdrawals").doc(id).update({ status: "paid", paidAt: admin.firestore.FieldValue.serverTimestamp() });
    console.log(`[AdminPayWithdrawal] Withdrawal ${id} marked as paid`);

    if (sellerId) {
      const sellerToken = await getUserFCMToken(sellerId);
      await sendFCM(sellerToken, "Withdrawal Approved! 💰", `₹${amount} sent to ${upiId} successfully`);
    }

    return res.json({ success: true });
  } catch (err) {
    console.error(`[AdminPayWithdrawal] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to process withdrawal payment" });
  }
});

// PATCH /api/admin/config
app.patch("/api/admin/config", authenticateAdmin, async (req, res) => {
  try {
    const { brandName, brandLogoUrl, adminEmail, adminPhone, commissionRate } = req.body;
    const updates = {};
    if (brandName !== undefined) updates.brandName = brandName;
    if (brandLogoUrl !== undefined) updates.brandLogoUrl = brandLogoUrl;
    if (adminEmail !== undefined) updates.adminEmail = adminEmail;
    if (adminPhone !== undefined) updates.adminPhone = adminPhone;
    if (commissionRate !== undefined) updates.commissionRate = parseFloat(commissionRate);

    await db.collection("config").doc("app_config").set(updates, { merge: true });
    return res.json({ success: true });
  } catch (err) {
    console.error(`[AdminConfig] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to update config" });
  }
});

// POST /api/admin/simulate-sale
app.post("/api/admin/simulate-sale", authenticateAdmin, async (req, res) => {
  try {
    const { productId, amount } = req.body;
    if (!productId || !amount) {
      return res.status(400).json({ error: "productId and amount are required" });
    }

    const parsedAmount = parseFloat(amount);
    if (isNaN(parsedAmount) || parsedAmount <= 0) {
      return res.status(400).json({ error: "amount must be a positive number" });
    }

    const [productDoc, configDoc] = await Promise.all([
      db.collection("products").doc(productId).get(),
      db.collection("config").doc("app_config").get(),
    ]);

    if (!productDoc.exists) {
      return res.status(404).json({ error: "Product not found" });
    }

    const { sellerId } = productDoc.data();
    const commissionRate = configDoc.exists ? configDoc.data().commissionRate || 10 : 10;
    const platformFee = parsedAmount * (commissionRate / 100);
    const sellerEarning = parsedAmount - platformFee;

    const batch = db.batch();

    const orderRef = db.collection("orders").doc();
    batch.set(orderRef, {
      buyerId: "SIMULATED",
      sellerId,
      productId,
      amountPaid: parsedAmount,
      platformFee,
      sellerEarning,
      status: "completed",
      simulated: true,
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    const sellerRef = db.collection("users").doc(sellerId);
    batch.update(sellerRef, {
      walletBalance: admin.firestore.FieldValue.increment(sellerEarning),
      totalEarnings: admin.firestore.FieldValue.increment(sellerEarning),
    });

    const productRef = db.collection("products").doc(productId);
    batch.update(productRef, { sales: admin.firestore.FieldValue.increment(1) });

    await batch.commit();
    console.log(`[SimulateSale] Sale simulated for product ${productId}: ₹${parsedAmount}`);

    const sellerToken = await getUserFCMToken(sellerId);
    await sendFCM(sellerToken, "🎉 New Sale!", `₹${sellerEarning} added to your wallet`);

    return res.json({ success: true, platformFee, sellerEarning });
  } catch (err) {
    console.error(`[SimulateSale] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to simulate sale" });
  }
});

// GET /api/admin/notifications
app.get("/api/admin/notifications", authenticateAdmin, async (req, res) => {
  try {
    const snapshot = await db
      .collection("notifications")
      .orderBy("createdAt", "desc")
      .limit(50)
      .get();

    const notifications = snapshot.docs.map((doc) => ({ id: doc.id, ...doc.data() }));
    return res.json({ notifications });
  } catch (err) {
    console.error(`[AdminNotifications] Error: ${err.message}`);
    return res.status(500).json({ error: "Failed to fetch notifications" });
  }
});

// ─────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────

app.use((err, req, res, next) => {
  console.error(`[UnhandledError] ${err.message}`, err.stack);
  return res.status(500).json({ error: "An unexpected error occurred" });
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`[Server] Digital Products Marketplace API running on port ${PORT}`);
});

module.exports = app;
