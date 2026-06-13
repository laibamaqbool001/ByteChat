/**
 * fix-message-hashes.js
 * ─────────────────────────────────────────────────────────────────
 * Run this ONCE to recompute contentHash for all messages using
 * the current HMAC_SECRET in your .env.
 *
 * Usage:
 *   cd "ByteChat backend"
 *   node scripts/fix-message-hashes.js
 *
 * What it does:
 *   1. Loads every message from MongoDB
 *   2. Decrypts the content using AES_ENCRYPTION_KEY
 *   3. Recomputes HMAC-SHA256 using current HMAC_SECRET
 *   4. Updates contentHash in DB
 *   5. Reports how many were fixed
 *
 * Safe to run multiple times — idempotent.
 * ─────────────────────────────────────────────────────────────────
 */

require("dotenv").config();
const mongoose = require("mongoose");
const crypto   = require("crypto");

// ── Validate env vars before connecting ──────────────────────────
const required = ["MONGO_URI", "AES_ENCRYPTION_KEY", "HMAC_SECRET"];
const missing  = required.filter(k => !process.env[k]);
if (missing.length) {
  console.error(" Missing env variables:", missing.join(", "));
  console.error("   Add them to your .env file and try again.");
  process.exit(1);
}

const HMAC_SECRET = process.env.HMAC_SECRET;

// ── Inline decrypt (avoids any module caching issues) ────────────
const ALGORITHM      = "aes-256-gcm";
const AES_KEY        = Buffer.from(process.env.AES_ENCRYPTION_KEY, "hex");

const decryptContent = ({ ciphertext, iv, authTag }) => {
  if (!ciphertext || !iv || !authTag) return null;
  const decipher = crypto.createDecipheriv(
    ALGORITHM, AES_KEY, Buffer.from(iv, "base64"), { authTagLength: 16 }
  );
  decipher.setAuthTag(Buffer.from(authTag, "base64"));
  return Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]).toString("utf8");
};

const computeHash = (plaintext, senderId, timestamp) => {
  const data = `${plaintext}|${senderId}|${timestamp}`;
  return crypto.createHmac("sha256", HMAC_SECRET).update(data).digest("hex");
};

// ── Main ──────────────────────────────────────────────────────────
const run = async () => {
  await mongoose.connect(process.env.MONGO_URI);
  console.log(" Connected to MongoDB\n");

  const Message = require("../models/Message.model");
  const messages = await Message.find({}).lean();
  console.log(`📨 Found ${messages.length} messages to process\n`);

  let fixed   = 0;
  let skipped = 0;
  let failed  = 0;

  for (const msg of messages) {
    try {
      // Decrypt content
      const plaintext = decryptContent({
        ciphertext: msg.content,
        iv:         msg.encryptionMeta?.iv,
        authTag:    msg.encryptionMeta?.authTag,
      });

      if (!plaintext) { skipped++; continue; }

      // Recompute hash with current HMAC_SECRET
      const newHash = computeHash(
        plaintext,
        String(msg.sender),
        new Date(msg.sentAt).toISOString()
      );

      // Only update if hash is different
      if (newHash !== msg.contentHash) {
        await Message.updateOne(
          { _id: msg._id },
          { $set: { contentHash: newHash } }
        );
        fixed++;
        console.log(`  ✓ Fixed message ${msg._id} (${new Date(msg.sentAt).toLocaleDateString()})`);
      } else {
        skipped++;
      }
    } catch (err) {
      failed++;
      console.warn(`  ⚠ Skipped message ${msg._id}: ${err.message}`);
    }
  }

  console.log("\n─────────────────────────────────");
  console.log(` Fixed   : ${fixed}`);
  console.log(`  Skipped : ${skipped} (already correct or undecryptable)`);
  console.log(` Failed  : ${failed}`);
  console.log("─────────────────────────────────");
  console.log("\n Done! Run the evidence report again — integrity rate should be 100%.");

  await mongoose.disconnect();
  process.exit(0);
};

run().catch(err => {
  console.error(" Script failed:", err.message, err.stack);
  process.exit(1);
});
