const admin = require("firebase-admin");

let app;

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);

  app = admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
} else {
  app = admin.app();
}

const db = admin.firestore();
const auth = admin.auth();

/**
 * Verifies a Firebase ID token and returns the decoded user object.
 * @param {string} token - Firebase ID token from Authorization header
 * @returns {Promise<admin.auth.DecodedIdToken>} Decoded user object
 */
async function verifyToken(token) {
  const decoded = await admin.auth().verifyIdToken(token);
  return decoded;
}

/**
 * Send an FCM notification to a single token.
 * Fails silently — never crashes the main flow.
 * @param {string} token - FCM device token
 * @param {string} title - Notification title
 * @param {string} body - Notification body
 * @param {Object} data - Optional key/value data payload
 */
async function sendFCM(token, title, body, data = {}) {
  if (!token) return;
  try {
    await admin.messaging().send({
      token,
      notification: { title, body },
      data: Object.fromEntries(
        Object.entries(data).map(([k, v]) => [k, String(v)])
      ),
    });
    console.log(`[FCM] Sent to token ${token.slice(0, 20)}...`);
  } catch (err) {
    console.error(`[FCM] Failed to send to token: ${err.message}`);
  }
}

/**
 * Send an FCM multicast notification to multiple tokens.
 * Fails silently — never crashes the main flow.
 * @param {string[]} tokens - Array of FCM device tokens
 * @param {string} title - Notification title
 * @param {string} body - Notification body
 * @param {Object} data - Optional key/value data payload
 * @returns {Promise<number>} Number of successful sends
 */
async function sendFCMMulticast(tokens, title, body, data = {}) {
  if (!tokens || tokens.length === 0) return 0;
  try {
    const response = await admin.messaging().sendEachForMulticast({
      tokens,
      notification: { title, body },
      data: Object.fromEntries(
        Object.entries(data).map(([k, v]) => [k, String(v)])
      ),
    });
    console.log(
      `[FCM Multicast] Success: ${response.successCount}, Failed: ${response.failureCount}`
    );
    return response.successCount;
  } catch (err) {
    console.error(`[FCM Multicast] Failed: ${err.message}`);
    return 0;
  }
}

/**
 * Fetch a user's FCM token from the fcm_tokens collection.
 * @param {string} userId
 * @returns {Promise<string|null>}
 */
async function getUserFCMToken(userId) {
  try {
    const tokenDoc = await db.collection("fcm_tokens").doc(userId).get();
    if (tokenDoc.exists) {
      return tokenDoc.data().token || null;
    }
    return null;
  } catch (err) {
    console.error(`[FCM] Failed to fetch token for user ${userId}: ${err.message}`);
    return null;
  }
}

module.exports = {
  admin,
  db,
  auth,
  verifyToken,
  sendFCM,
  sendFCMMulticast,
  getUserFCMToken,
};
