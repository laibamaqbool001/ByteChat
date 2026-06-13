const express = require("express");
const router = express.Router();
const { getMe, updateProfile, uploadProfilePicture, searchUsers, getUserByUsername, listFriends } = require("../controllers/user.controller");
const { protect } = require("../middleware/auth.middleware");
const { captureMetadata } = require("../middleware/metadata.middleware");
const { upload } = require("../config/cloudinary");

router.use(protect, captureMetadata);

router.get("/me",           getMe);
router.patch("/me",         updateProfile);
router.post("/me/avatar",   upload.single("avatar"), uploadProfilePicture);
router.get("/me/friends",   listFriends);
router.get("/search",       searchUsers);
router.get("/:username",    getUserByUsername);

module.exports = router;