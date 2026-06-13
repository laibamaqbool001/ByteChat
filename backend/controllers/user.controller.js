const User = require("../models/User.model");
const { cloudinary, uploadToCloudinary } = require("../config/cloudinary");
const { logAction } = require("../services/audit.service");

exports.getMe = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate("friends", "username displayName profilePicture lastSeen");
    res.json({ success: true, data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};

exports.updateProfile = async (req, res) => {
  try {
    const { displayName, bio } = req.body;
    const user = await User.findByIdAndUpdate(req.user._id, { displayName, bio }, { new: true, runValidators: true });
    await logAction({ req, actor: { userId: user._id, username: user.username }, action: "PROFILE_UPDATED", targetType: "User", targetId: user._id, details: { displayName, bio } });
    res.json({ success: true, message: "Profile updated", data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};

exports.uploadProfilePicture = async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ success: false, message: "No image provided" });

    const user = await User.findById(req.user._id);
    if (user.profilePicture?.publicId) {
      try { await cloudinary.uploader.destroy(user.profilePicture.publicId); } catch (_) {}
    }

    const result = await uploadToCloudinary(req.file.buffer, "bytechat/avatars");

    user.profilePicture = { url: result.secure_url, publicId: result.public_id };
    await user.save();

    await logAction({ req, actor: { userId: user._id, username: user.username }, action: "PROFILE_PICTURE_UPDATED", targetType: "User", targetId: user._id });
    res.json({ success: true, message: "Profile picture updated", data: { profilePicture: user.profilePicture } });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};

exports.searchUsers = async (req, res) => {
  try {
    const { q } = req.query;
    if (!q || q.trim().length < 2) return res.status(400).json({ success: false, message: "Search query must be at least 2 characters" });

    const currentUser = await User.findById(req.user._id).select("blockedUsers");
    const users = await User.find({
      username: { $regex: q.trim(), $options: "i" },
      _id: { $ne: req.user._id, $nin: currentUser.blockedUsers },
      isActive: true,
    }).select("username displayName profilePicture bio").limit(20);

    res.json({ success: true, data: users });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};

exports.getUserByUsername = async (req, res) => {
  try {
    const user = await User.findOne({ username: req.params.username, isActive: true })
      .select("username displayName profilePicture bio createdAt");
    if (!user) return res.status(404).json({ success: false, message: "User not found" });
    res.json({ success: true, data: user });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};

exports.listFriends = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).populate("friends", "username displayName profilePicture lastSeen bio");
    res.json({ success: true, data: user.friends });
  } catch (err) { res.status(500).json({ success: false, message: err.message }); }
};
