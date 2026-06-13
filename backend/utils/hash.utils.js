const crypto = require("crypto");

const HMAC_SECRET = process.env.HMAC_SECRET || "fallback_hmac_secret_change_me";
const EVIDENCE_SECRET = process.env.EVIDENCE_EXPORT_SECRET || "fallback_evidence_secret";

/**
 * Compute HMAC-SHA256 of message content.
 * ALWAYS called on PLAINTEXT — before encryption on write,
 * after decryption on verify. This ensures tamper detection
 * works on the actual readable content, not ciphertext.
 *
 * Input: plaintext content + senderId + ISO timestamp
 */
const computeMessageHash = (plaintext, senderId, timestamp) => {
  const data = `${plaintext}|${senderId}|${timestamp}`;
  return crypto.createHmac("sha256", HMAC_SECRET).update(data).digest("hex");
};

/**
 * Verify a message's stored hash against its decrypted content.
 * Caller must pass the already-decrypted plaintext.
 * Returns: { intact: bool, expected: string, stored: string }
 */
const verifyMessageHash = (message, decryptedContent) => {
  // decryptedContent must be passed in — this util doesn't do decryption
  const content = decryptedContent !== undefined ? decryptedContent : message.content;
  const expected = computeMessageHash(
    content,
    message.sender.toString(),
    message.sentAt.toISOString()
  );
  return {
    intact: expected === message.contentHash,
    expected,
    stored: message.contentHash,
  };
};

/**
 * Compute SHA-256 hash of any JSON object (for report integrity)
 */
const computeObjectHash = (obj) => {
  const str = JSON.stringify(obj, Object.keys(obj).sort());
  return crypto.createHash("sha256").update(str).digest("hex");
};

/**
 * Generate HMAC-signed digital signature for evidence reports
 */
const signEvidenceReport = (reportId, reportHash, generatedAt) => {
  const data = `${reportId}|${reportHash}|${generatedAt}`;
  return crypto.createHmac("sha256", EVIDENCE_SECRET).update(data).digest("hex");
};

/**
 * Verify evidence report signature
 */
const verifyEvidenceSignature = (reportId, reportHash, generatedAt, storedSignature) => {
  const expected = signEvidenceReport(reportId, reportHash, generatedAt);
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(storedSignature));
};

/**
 * Compute a hash for an audit log entry (prevents log tampering)
 */
const computeAuditEntryHash = (entry) => {
  const data = `${entry.actor?.userId}|${entry.action}|${entry.targetId}|${entry.timestamp}`;
  return crypto.createHmac("sha256", HMAC_SECRET).update(data).digest("hex");
};

module.exports = {
  computeMessageHash,
  verifyMessageHash,
  computeObjectHash,
  signEvidenceReport,
  verifyEvidenceSignature,
  computeAuditEntryHash,
};
