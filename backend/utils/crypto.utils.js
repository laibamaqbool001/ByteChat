/**
 * ByteChat E2EE Crypto Utility
 * ─────────────────────────────────────────────────────────────────
 * Architecture: Signal-protocol-inspired, server-side Node.js crypto
 *
 * Key exchange:  ECDH (P-256 curve)
 * Message enc:   AES-256-GCM  (authenticated encryption)
 * Key hashing:   HKDF-SHA256  (key derivation from ECDH shared secret)
 * Identity:      ECDSA P-256  (key signing / sender verification)
 *
 * What the SERVER stores:
 *   - Public keys only (ECDH identity key, signed prekey, one-time prekeys)
 *   - Encrypted ciphertext + IV + GCM auth tag + ephemeral public key
 *   - HMAC of the ciphertext (tamper detection on the encrypted layer)
 *
 * What the SERVER never sees:
 *   - Private keys (generated client-side, stay on device)
 *   - Plaintext message content
 *
 * Flow (simplified X3DH / Double-Ratchet lite):
 *   1. Sender fetches receiver's public key bundle from server
 *   2. Sender generates ephemeral ECDH keypair
 *   3. ECDH(senderEphemeral.private, receiver.public) → sharedSecret
 *   4. HKDF(sharedSecret) → 32-byte AES key
 *   5. AES-256-GCM encrypt(plaintext, aesKey, iv) → { ciphertext, authTag }
 *   6. Sender sends: { ciphertext, iv, authTag, ephemeralPublicKey } to server
 *   7. Receiver fetches message, uses their private key to reproduce sharedSecret
 *   8. Receiver decrypts ciphertext
 */

const crypto = require("crypto");

// ── ECDH Key Generation ───────────────────────────────────────────

/**
 * Generate an ECDH P-256 keypair.
 * In a real app the private key is generated client-side and NEVER sent to server.
 * This function is provided for testing / server-side key operations only.
 *
 * @returns {{ privateKey: string, publicKey: string }} Both as base64 DER
 */
const generateECDHKeyPair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return {
    privateKey: privateKey.toString("base64"),
    publicKey: publicKey.toString("base64"),
  };
};

/**
 * Generate an ECDSA P-256 keypair for identity/signing.
 */
const generateIdentityKeyPair = () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "P-256",
    publicKeyEncoding: { type: "spki", format: "der" },
    privateKeyEncoding: { type: "pkcs8", format: "der" },
  });
  return {
    privateKey: privateKey.toString("base64"),
    publicKey: publicKey.toString("base64"),
  };
};

// ── ECDH Shared Secret Derivation ────────────────────────────────

/**
 * Derive a shared secret using ECDH.
 * @param {string} privateKeyB64  - Your private key (base64 PKCS8 DER)
 * @param {string} publicKeyB64   - Peer's public key (base64 SPKI DER)
 * @returns {Buffer} Raw 32-byte shared secret
 */
const deriveSharedSecret = (privateKeyB64, publicKeyB64) => {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const publicKey = crypto.createPublicKey({
    key: Buffer.from(publicKeyB64, "base64"),
    format: "der",
    type: "spki",
  });

  return crypto.diffieHellman({ privateKey, publicKey });
};

// ── HKDF Key Derivation ───────────────────────────────────────────

/**
 * Derive a 32-byte AES key from ECDH shared secret using HKDF-SHA256.
 * @param {Buffer} sharedSecret
 * @param {string} [info="ByteChat-E2EE-v1"]  - Context label
 * @returns {Buffer} 32-byte AES-256 key
 */
const deriveAESKey = (sharedSecret, info = "ByteChat-E2EE-v1") => {
  // HKDF extract
  const prk = crypto.createHmac("sha256", Buffer.alloc(32, 0))
    .update(sharedSecret)
    .digest();

  // HKDF expand (T(1) only, 32 bytes)
  const infoBuffer = Buffer.from(info, "utf8");
  const counter = Buffer.from([0x01]);
  const aesKey = crypto.createHmac("sha256", prk)
    .update(Buffer.concat([infoBuffer, counter]))
    .digest();

  return aesKey; // 32 bytes → AES-256
};

// ── AES-256-GCM Encryption ────────────────────────────────────────

/**
 * Encrypt plaintext using AES-256-GCM.
 * The GCM auth tag provides both confidentiality AND integrity.
 *
 * @param {string} plaintext
 * @param {Buffer} aesKey          - 32-byte key
 * @returns {{ ciphertext: string, iv: string, authTag: string }}
 *   All base64-encoded. Store all three — all needed for decryption.
 */
const encryptAES256GCM = (plaintext, aesKey) => {
  const iv = crypto.randomBytes(12); // 96-bit IV — recommended for GCM
  const cipher = crypto.createCipheriv("aes-256-gcm", aesKey, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const authTag = cipher.getAuthTag(); // 16-byte GCM tag

  return {
    ciphertext: encrypted.toString("base64"),
    iv: iv.toString("base64"),
    authTag: authTag.toString("base64"),
  };
};

/**
 * Decrypt AES-256-GCM ciphertext.
 * Throws if auth tag verification fails (tampered ciphertext).
 *
 * @param {string} ciphertextB64
 * @param {string} ivB64
 * @param {string} authTagB64
 * @param {Buffer} aesKey
 * @returns {string} Plaintext
 */
const decryptAES256GCM = (ciphertextB64, ivB64, authTagB64, aesKey) => {
  const iv = Buffer.from(ivB64, "base64");
  const authTag = Buffer.from(authTagB64, "base64");
  const ciphertext = Buffer.from(ciphertextB64, "base64");

  const decipher = crypto.createDecipheriv("aes-256-gcm", aesKey, iv);
  decipher.setAuthTag(authTag);

  return Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]).toString("utf8");
  // Will throw "Unsupported state or unable to authenticate data" if tampered
};

// ── Full E2EE Encrypt (sender side) ──────────────────────────────

/**
 * Full sender-side encryption.
 * In production this runs on the CLIENT. Provided here for:
 *   - Server-to-server messaging
 *   - Testing
 *   - Backend-side encryption as a fallback (opt-in)
 *
 * @param {string} plaintext
 * @param {string} receiverPublicKeyB64 - Receiver's ECDH public key (base64)
 * @returns {{
 *   ciphertext: string,
 *   iv: string,
 *   authTag: string,
 *   ephemeralPublicKey: string,
 *   algorithm: string
 * }}
 */
const e2eeEncrypt = (plaintext, receiverPublicKeyB64) => {
  // 1. Generate fresh ephemeral ECDH keypair (one per message)
  const ephemeral = generateECDHKeyPair();

  // 2. ECDH: ephemeral private × receiver public → shared secret
  const sharedSecret = deriveSharedSecret(ephemeral.privateKey, receiverPublicKeyB64);

  // 3. HKDF → 32-byte AES key
  const aesKey = deriveAESKey(sharedSecret);

  // 4. AES-256-GCM encrypt
  const { ciphertext, iv, authTag } = encryptAES256GCM(plaintext, aesKey);

  // ephemeral private key is discarded — forward secrecy
  return {
    ciphertext,
    iv,
    authTag,
    ephemeralPublicKey: ephemeral.publicKey,
    algorithm: "ECDH-P256+AES-256-GCM",
  };
};

/**
 * Full receiver-side decryption.
 * In production this runs on the CLIENT.
 *
 * @param {string} ciphertextB64
 * @param {string} ivB64
 * @param {string} authTagB64
 * @param {string} ephemeralPublicKeyB64 - Sender's ephemeral public key
 * @param {string} receiverPrivateKeyB64 - Receiver's private key (stays on device!)
 * @returns {string} Plaintext
 */
const e2eeDecrypt = (ciphertextB64, ivB64, authTagB64, ephemeralPublicKeyB64, receiverPrivateKeyB64) => {
  // 1. ECDH: receiver private × sender ephemeral public → same shared secret
  const sharedSecret = deriveSharedSecret(receiverPrivateKeyB64, ephemeralPublicKeyB64);

  // 2. HKDF → same AES key
  const aesKey = deriveAESKey(sharedSecret);

  // 3. AES-256-GCM decrypt (throws if auth tag fails)
  return decryptAES256GCM(ciphertextB64, ivB64, authTagB64, aesKey);
};

// ── Key Signing (ECDSA) ───────────────────────────────────────────

/**
 * Sign data with an ECDSA private key.
 * Used to sign prekeys so receivers can verify authenticity.
 *
 * @param {string|Buffer} data
 * @param {string} privateKeyB64  - ECDSA P-256 private key (base64 PKCS8 DER)
 * @returns {string} Signature (base64)
 */
const signData = (data, privateKeyB64) => {
  const privateKey = crypto.createPrivateKey({
    key: Buffer.from(privateKeyB64, "base64"),
    format: "der",
    type: "pkcs8",
  });
  const sign = crypto.createSign("SHA256");
  sign.update(data);
  return sign.sign(privateKey, "base64");
};

/**
 * Verify an ECDSA signature.
 * @param {string|Buffer} data
 * @param {string} signatureB64
 * @param {string} publicKeyB64  - ECDSA P-256 public key (base64 SPKI DER)
 * @returns {boolean}
 */
const verifySignature = (data, signatureB64, publicKeyB64) => {
  try {
    const publicKey = crypto.createPublicKey({
      key: Buffer.from(publicKeyB64, "base64"),
      format: "der",
      type: "spki",
    });
    const verify = crypto.createVerify("SHA256");
    verify.update(data);
    return verify.verify(publicKey, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
};

// ── Password Hashing (bcrypt wrapper, re-exported for convenience) ─

const bcrypt = require("bcryptjs");

const hashPassword = (password) => bcrypt.hash(password, 12);
const comparePassword = (password, hash) => bcrypt.compare(password, hash);

// ── Utility: hash any string SHA-256 ──────────────────────────────

const sha256 = (data) =>
  crypto.createHash("sha256").update(data).digest("hex");

module.exports = {
  // Key generation
  generateECDHKeyPair,
  generateIdentityKeyPair,
  // Key exchange
  deriveSharedSecret,
  deriveAESKey,
  // Symmetric encryption
  encryptAES256GCM,
  decryptAES256GCM,
  // High-level E2EE
  e2eeEncrypt,
  e2eeDecrypt,
  // Signing
  signData,
  verifySignature,
  // Password hashing
  hashPassword,
  comparePassword,
  // Misc
  sha256,
};
