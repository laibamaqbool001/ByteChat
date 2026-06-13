/**
 * scripts/rotate-encryption-key.js
 * ──────────────────────────────────────────────────────────────────
 * Run this AFTER setting AES_ENCRYPTION_KEY_OLD = old key and
 * AES_ENCRYPTION_KEY = new key in your .env / secrets manager.
 *
 * This script re-encrypts every message's content and metadata
 * fields from the old key to the new key.
 *
 * Usage:
 *   node scripts/rotate-encryption-key.js
 *
 * Safety:
 *   - Processes in batches of 100
 *   - Skips messages already on the current key version
 *   - Logs progress and errors without crashing the whole run
 */

require("dotenv").config();
const mongoose = require("mongoose");
const Message = require("../models/Message.model");
const { decrypt, encrypt, CURRENT_KEY_VERSION } = require("../utils/encryption.utils");

const BATCH_SIZE = 100;

const rotateMessages = async () => {
  await mongoose.connect(process.env.MONGO_URI);
  console.log("✅ Connected to MongoDB\n");

  const total = await Message.countDocuments({
    "encryptionMeta.keyVersion": { $lt: CURRENT_KEY_VERSION },
  });

  console.log(`📦 Messages to rotate: ${total}`);
  if (total === 0) {
    console.log("Nothing to rotate. All messages are on the current key version.");
    process.exit(0);
  }

  let processed = 0;
  let errors = 0;
  let skip = 0;

  while (true) {
    const batch = await Message.find({
      "encryptionMeta.keyVersion": { $lt: CURRENT_KEY_VERSION },
    }).limit(BATCH_SIZE);

    if (batch.length === 0) break;

    for (const msg of batch) {
      try {
        // Re-encrypt content
        const plainContent = decrypt(msg.encryptionMeta);
        const newEncrypted = encrypt(plainContent);
        msg.content = newEncrypted.ciphertext;
        msg.encryptionMeta = {
          iv: newEncrypted.iv,
          authTag: newEncrypted.authTag,
          keyVersion: newEncrypted.keyVersion,
        };

        // Re-encrypt metadata fields if present
        const METADATA_FIELDS = ["senderIp", "senderDevice", "senderPlatform", "receiverIp", "receiverDevice"];
        for (const field of METADATA_FIELDS) {
          const val = msg.metadata?.[field];
          if (val && typeof val === "object" && val.ciphertext) {
            const plain = decrypt(val);
            const newEnc = encrypt(plain);
            msg.metadata[field] = newEnc;
          }
        }

        // Re-encrypt editHistory entries
        for (const edit of msg.editHistory || []) {
          if (edit.previousContent && typeof edit.previousContent === "object" && edit.previousContent.ciphertext) {
            const plain = decrypt(edit.previousContent);
            edit.previousContent = encrypt(plain);
          }
        }

        await msg.save();
        processed++;
      } catch (err) {
        console.error(`❌ Failed to rotate message ${msg._id}: ${err.message}`);
        errors++;
      }
    }

    skip += batch.length;
    console.log(`  Rotated ${processed} / ${total} (${errors} errors)...`);
  }

  console.log(`\n✅ Rotation complete. ${processed} rotated, ${errors} errors.`);
  if (errors === 0) {
    console.log("🟢 Safe to clear AES_ENCRYPTION_KEY_OLD from your .env");
  } else {
    console.log("🔴 Some messages failed — investigate before clearing AES_ENCRYPTION_KEY_OLD");
  }

  await mongoose.disconnect();
};

rotateMessages().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
