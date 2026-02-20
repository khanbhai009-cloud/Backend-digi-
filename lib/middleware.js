const { verifyToken } = require("./firebase");

/**
 * Extracts and verifies a Firebase Bearer token from the Authorization header.
 * Attaches the decoded user to req.user.
 */
async function authenticateUser(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split("Bearer ")[1].trim();

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const decoded = await verifyToken(token);
    req.user = decoded;
    return next();
  } catch (err) {
    console.error(`[Auth] Token verification failed: ${err.message}`);
    return res.status(401).json({ error: "Invalid token" });
  }
}

/**
 * Verifies the user is authenticated and matches the configured admin email.
 * Must be used AFTER authenticateUser or it will run authenticateUser first.
 */
async function authenticateAdmin(req, res, next) {
  await authenticateUser(req, res, async () => {
    if (req.user.email !== process.env.ADMIN_EMAIL) {
      return res.status(403).json({ error: "Admin access required" });
    }
    return next();
  });
}

module.exports = { authenticateUser, authenticateAdmin };
