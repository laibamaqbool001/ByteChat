/**
 * scripts/generate-keys.js
 * ──────────────────────────────────────────────────────────────────
 * Run once to generate all secrets needed in your .env file.
 *
 * Usage:
 *   node scripts/generate-keys.js
 */

const crypto = require("crypto");

const generateHex = (bytes) => crypto.randomBytes(bytes).toString("hex");

console.log("\n🔐 ByteChat — Secret Key Generator\n");
console.log("Copy these into your .env file:\n");
console.log("# JWT");
console.log(`JWT_SECRET=${generateHex(32)}`);
console.log(`JWT_REFRESH_SECRET=${generateHex(32)}`);
console.log("");
console.log("# Forensics / HMAC");
console.log(`HMAC_SECRET=${generateHex(32)}`);
console.log(`EVIDENCE_EXPORT_SECRET=${generateHex(32)}`);
console.log(`CHAIN_OF_CUSTODY_SECRET=${generateHex(32)}`);
console.log("");
console.log("# AES-256 Encryption (KEEP THESE SAFE — losing them = losing all messages)");
console.log(`AES_ENCRYPTION_KEY=${generateHex(32)}`);
console.log(`AES_KEY_VERSION=1`);
console.log(`# AES_ENCRYPTION_KEY_OLD=   ← only set this during key rotation`);
console.log("");
console.log("⚠️  Store these in a secrets manager (AWS Secrets Manager, HashiCorp Vault)");
console.log("    in production. Never commit .env to git.\n");
