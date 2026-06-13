/**
 * encryption.utils.js
 * ───────────────────────────────────────────────────────────────────
 * AES-256-GCM server-side encryption for ByteChat.
 *
 * Algorithm : AES-256-GCM
 *   • 256-bit key  → brute-force infeasible
 *   • GCM mode     → authenticated encryption, detects ciphertext tampering
 *                    via the 16-byte auth tag (built-in integrity check)
 *   • Random IV    → unique per message, stored alongside ciphertext
 *
 * What gets encrypted at rest:
 *   • message.content          (plaintext → ciphertext in DB)
 *   • message.metadata fields  (IP address, device string)
 *   • editHistory entries      (previous content versions)
 *
 * Key management:
 *   • Primary key  : AES_ENCRYPTION_KEY  (env, 64 hex chars = 32 bytes)
 *   • Previous key : AES_ENCRYPTION_KEY_OLD (env, optional — for rotation)
 *   • Key version  : stored on each encrypted record so we know which
 *                    key to use for decryption during rotation windows
 *
 * Key rotation workflow:
 *   1. Set AES_ENCRYPTION_KEY_OLD = current AES_ENCRYPTION_KEY
 *   2. Generate a new AES_ENCRYPTION_KEY
 *   3. Deploy — new messages use new key, old messages decrypt with old key
 *   4. Run migration script to re-encrypt old messages with new key
 *   5. Once migration done, clear AES_ENCRYPTION_KEY_OLD
 * ───────────────────────────────────────────────────────────────────
 */

const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const IV_LENGTH = 12;        // 96 bits — GCM recommended IV size
const AUTH_TAG_LENGTH = 16;  // 128 bits — GCM default, maximum security

// ── Key loading ───────────────────────────────────────────────────

/**
 * Load a 32-byte AES key from a 64-char hex env variable.
 * Throws clearly if the key is missing or wrong length.
 */
const loadKey = (envVar) => {
  const hex = process.env[envVar];
  if (!hex) throw new Error(`Missing env variable: ${envVar}`);
  if (hex.length !== 64) {
    throw new Error(
      `${envVar} must be exactly 64 hex characters (32 bytes). ` +
      `Got ${hex.length}. Generate with: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`
    );
  }
  return Buffer.from(hex, "hex");
};

// Lazy-load keys so missing env vars only throw at runtime, not import time
let _primaryKey = null;
let _oldKey = null;

const getPrimaryKey = () => {
  if (!_primaryKey) _primaryKey = loadKey("AES_ENCRYPTION_KEY");
  return _primaryKey;
};

const getOldKey = () => {
  if (!process.env.AES_ENCRYPTION_KEY_OLD) return null;
  if (!_oldKey) _oldKey = loadKey("AES_ENCRYPTION_KEY_OLD");
  return _oldKey;
};

// Current key version — bump when rotating keys
const CURRENT_KEY_VERSION = parseInt(process.env.AES_KEY_VERSION || "1", 10);

// ── Core encrypt / decrypt ────────────────────────────────────────

/**
 * Encrypt a plaintext string.
 *
 * @param   {string} plaintext
 * @returns {{ ciphertext: string, iv: string, authTag: string, keyVersion: number }}
 *          All fields are base64 strings, safe to store in MongoDB.
 */
const encrypt = (plaintext) => {
  if (plaintext === null || plaintext === undefined) return null;

  const key = getPrimaryKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), "utf8"),
    cipher.final(),
  ]);

  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    authTag: cipher.getAuthTag().toString("base64"),
    keyVersion: CURRENT_KEY_VERSION,
  };
};

/**
 * Decrypt an encrypted record.
 *
 * @param   {{ ciphertext: string, iv: string, authTag: string, keyVersion?: number }} encryptedObj
 * @returns {string} plaintext
 * @throws  if auth tag fails (ciphertext was tampered with)
 */
const decrypt = ({ ciphertext, iv, authTag, keyVersion }) => {
  if (!ciphertext || !iv || !authTag) return null;

  // Choose the right key based on version
  const key = (keyVersion && keyVersion < CURRENT_KEY_VERSION)
    ? (getOldKey() || getPrimaryKey())
    : getPrimaryKey();

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    key,
    Buffer.from(iv, "base64"),
    { authTagLength: AUTH_TAG_LENGTH }
  );
  decipher.setAuthTag(Buffer.from(authTag, "base64"));

  // GCM auth tag check happens here — throws if tampered
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
};

/**
 * Re-encrypt with the current primary key (used during key rotation).
 * Decrypt with old key → encrypt with new key.
 */
const reEncrypt = (encryptedObj) => {
  const plaintext = decrypt(encryptedObj);
  return encrypt(plaintext);
};

// ── Field-level helpers ───────────────────────────────────────────

/**
 * Encrypt a plain object's string fields by key name.
 * Returns a new object with encrypted versions of the specified fields.
 *
 * Example:
 *   encryptFields({ senderIp: "1.2.3.4", senderDevice: "Chrome" }, ["senderIp", "senderDevice"])
 *   → { senderIp: { ciphertext, iv, authTag, keyVersion }, senderDevice: { ... } }
 */
const encryptFields = (obj, fields) => {
  const result = { ...obj };
  for (const field of fields) {
    if (result[field]) {
      result[field] = encrypt(result[field]);
    }
  }
  return result;
};

/**
 * Decrypt specific fields of an object in place.
 * Non-encrypted fields (plain strings) are left untouched.
 */
const decryptFields = (obj, fields) => {
  if (!obj) return obj;
  const result = { ...obj };
  for (const field of fields) {
    const val = result[field];
    // Only attempt decrypt if it looks like our encrypted object
    if (val && typeof val === "object" && val.ciphertext && val.iv && val.authTag) {
      try {
        result[field] = decrypt(val);
      } catch {
        result[field] = "[decryption failed]";
      }
    }
  }
  return result;
};

// ── Utility ───────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure AES-256 key.
 * Print to console — copy into your .env as AES_ENCRYPTION_KEY.
 */
const generateKey = () => crypto.randomBytes(32).toString("hex");

/**
 * Check if a value is an encrypted object (has our envelope shape).
 */
const isEncryptedObject = (val) =>
  val && typeof val === "object" && typeof val.ciphertext === "string" && typeof val.iv === "string";

module.exports = {
  encrypt,
  decrypt,
  reEncrypt,
  encryptFields,
  decryptFields,
  generateKey,
  isEncryptedObject,
  CURRENT_KEY_VERSION,
};
