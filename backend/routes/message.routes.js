const express = require("express");
const router  = express.Router();
const {
  sendMessage,
  sendImage,
  editImage,
  getConversation,
  deleteMessage,
  editMessage,
  verifyImageHash,
  verifyTextIntegrity,
  aiImageEditProxy,
} = require("../controllers/message.controller");
const { protect }          = require("../middleware/auth.middleware");
const { captureMetadata }  = require("../middleware/metadata.middleware");
const { upload }           = require("../config/cloudinary");

router.use(protect, captureMetadata);

router.post("/",                                       sendMessage);
router.post("/image",        upload.single("image"),   sendImage);
router.get("/conversation/:username",                  getConversation);
router.delete("/:messageId",                           deleteMessage);
router.patch("/:messageId",                            editMessage);

// Replace image (records old in imageEditHistory → shows "edited" badge)
router.patch("/:messageId/image",       upload.single("image"), editImage);

// AI image-edit instruction proxy — browser can't call Anthropic directly (CORS)
// Frontend sends { imageUrl, editType, prompt } → we call Claude → return editSpec
router.post("/ai-edit-proxy",  aiImageEditProxy);

// Forensic endpoints (data stored in DB — no UI buttons for these)
router.post("/:messageId/verify-image", upload.single("image"), verifyImageHash);
router.get("/:messageId/verify-text",   verifyTextIntegrity);

module.exports = router;