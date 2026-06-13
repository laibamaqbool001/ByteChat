const jwt = require("jsonwebtoken");

/**
 * Generate a short-lived access token (15 min default)
 */
const generateAccessToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN || "15m",
  });
};

/**
 * Generate a long-lived refresh token (7 days default)
 */
const generateRefreshToken = (userId) => {
  return jwt.sign({ id: userId }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || "7d",
  });
};

/**
 * Verify a refresh token — returns decoded payload or throws
 */
const verifyRefreshToken = (token) => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
};

/**
 * Generate a short-lived message signing token (sender verification)
 * Signed with sender's ID + timestamp — used in forensic message verification
 */
const generateMessageSignature = (senderId, messageId, timestamp) => {
  return jwt.sign(
    { senderId, messageId, timestamp },
    process.env.JWT_SECRET,
    { expiresIn: "1y" } // Long-lived for evidence purposes
  );
};

/**
 * Verify a message signature
 */
const verifyMessageSignature = (signature) => {
  try {
    return jwt.verify(signature, process.env.JWT_SECRET);
  } catch {
    return null;
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateMessageSignature,
  verifyMessageSignature,
};
