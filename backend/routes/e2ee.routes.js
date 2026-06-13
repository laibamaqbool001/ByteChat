const express = require("express");
const router = express.Router();
const {
  registerKeys,
  getKeyBundle,
  uploadPreKeys,
  getMyKeyStatus,
  verifyPreKeySignature,
} = require("../controllers/e2ee.controller");
const { protect } = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");

router.use(protect, captureMetadata);

router.post("/keys", registerKeys);                    // Register full key bundle
router.get("/keys/me", getMyKeyStatus);                // Own key status
router.post("/keys/prekeys", uploadPreKeys);            // Replenish one-time prekeys
router.get("/keys/:username", getKeyBundle);            // Fetch key bundle to encrypt for user
router.post("/verify", verifyPreKeySignature);          // Verify a prekey signature

module.exports = router;
