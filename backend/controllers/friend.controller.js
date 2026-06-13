const User = require("../models/User.model");
const FriendRequest = require("../models/FriendRequest.model");
const { logAction } = require("../services/audit.service");

// ── Send friend request ────────────────────────────────────────────
exports.sendRequest = async (req, res) => {
  try {
    const { username } = req.body;
    const receiver = await User.findOne({ username: username?.toLowerCase(), isActive: true });

    if (!receiver) return res.status(404).json({ success: false, message: "User not found" });
    if (receiver._id.equals(req.user._id))
      return res.status(400).json({ success: false, message: "Cannot send request to yourself" });

    // Check if blocked
    const currentUser = await User.findById(req.user._id).select("blockedUsers friends");
    if (currentUser.blockedUsers.includes(receiver._id))
      return res.status(400).json({ success: false, message: "Cannot send request to a blocked user" });

    if (currentUser.friends.includes(receiver._id))
      return res.status(400).json({ success: false, message: "Already friends" });

    // Check for existing request
    const existing = await FriendRequest.findOne({
      $or: [
        { sender: req.user._id, receiver: receiver._id },
        { sender: receiver._id, receiver: req.user._id },
      ],
      status: "pending",
    });
    if (existing) return res.status(409).json({ success: false, message: "A pending request already exists" });

    const request = await FriendRequest.create({
      sender: req.user._id,
      receiver: receiver._id,
      statusHistory: [{ status: "pending", changedByIp: req.clientMeta?.ip }],
    });

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "FRIEND_REQUEST_SENT",
      targetType: "FriendRequest",
      targetId: request._id,
      details: { to: receiver.username },
    });

    res.status(201).json({ success: true, message: "Friend request sent", data: request });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Accept request ─────────────────────────────────────────────────
exports.acceptRequest = async (req, res) => {
  try {
    const request = await FriendRequest.findById(req.params.requestId);
    if (!request) return res.status(404).json({ success: false, message: "Request not found" });
    if (!request.receiver.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Not authorized" });
    if (request.status !== "pending")
      return res.status(400).json({ success: false, message: `Request is already ${request.status}` });

    request.status = "accepted";
    request.statusHistory.push({ status: "accepted", changedByIp: req.clientMeta?.ip });
    await request.save();

    // Add each other as friends
    await User.findByIdAndUpdate(request.sender, { $addToSet: { friends: request.receiver } });
    await User.findByIdAndUpdate(request.receiver, { $addToSet: { friends: request.sender } });

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "FRIEND_REQUEST_ACCEPTED",
      targetType: "FriendRequest",
      targetId: request._id,
      details: { sender: request.sender },
    });

    res.json({ success: true, message: "Friend request accepted" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Decline request ────────────────────────────────────────────────
exports.declineRequest = async (req, res) => {
  try {
    const request = await FriendRequest.findById(req.params.requestId);
    if (!request) return res.status(404).json({ success: false, message: "Request not found" });
    if (!request.receiver.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Not authorized" });
    if (request.status !== "pending")
      return res.status(400).json({ success: false, message: `Request is already ${request.status}` });

    request.status = "declined";
    request.statusHistory.push({ status: "declined", changedByIp: req.clientMeta?.ip });
    await request.save();

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "FRIEND_REQUEST_DECLINED",
      targetType: "FriendRequest",
      targetId: request._id,
    });

    res.json({ success: true, message: "Friend request declined" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Cancel request (sender cancels) ───────────────────────────────
exports.cancelRequest = async (req, res) => {
  try {
    const request = await FriendRequest.findById(req.params.requestId);
    if (!request) return res.status(404).json({ success: false, message: "Request not found" });
    if (!request.sender.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Only the sender can cancel" });
    if (request.status !== "pending")
      return res.status(400).json({ success: false, message: `Request is already ${request.status}` });

    request.status = "cancelled";
    request.statusHistory.push({ status: "cancelled", changedByIp: req.clientMeta?.ip });
    await request.save();

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "FRIEND_REQUEST_CANCELLED",
      targetType: "FriendRequest",
      targetId: request._id,
    });

    res.json({ success: true, message: "Friend request cancelled" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Remove friend ──────────────────────────────────────────────────
exports.removeFriend = async (req, res) => {
  try {
    const { username } = req.body;
    const friend = await User.findOne({ username: username?.toLowerCase() });
    if (!friend) return res.status(404).json({ success: false, message: "User not found" });

    await User.findByIdAndUpdate(req.user._id, { $pull: { friends: friend._id } });
    await User.findByIdAndUpdate(friend._id, { $pull: { friends: req.user._id } });

    // Also update the friend request record for audit trail
    await FriendRequest.findOneAndUpdate(
      {
        $or: [
          { sender: req.user._id, receiver: friend._id },
          { sender: friend._id, receiver: req.user._id },
        ],
        status: "accepted",
      },
      { status: "cancelled" }
    );

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "FRIEND_REMOVED",
      targetType: "User",
      targetId: friend._id,
      details: { removedUsername: friend.username },
    });

    res.json({ success: true, message: `${friend.username} removed from friends` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Block user ─────────────────────────────────────────────────────
exports.blockUser = async (req, res) => {
  try {
    const { username } = req.body;
    const target = await User.findOne({ username: username?.toLowerCase() });
    if (!target) return res.status(404).json({ success: false, message: "User not found" });
    if (target._id.equals(req.user._id))
      return res.status(400).json({ success: false, message: "Cannot block yourself" });

    await User.findByIdAndUpdate(req.user._id, {
      $addToSet: { blockedUsers: target._id },
      $pull: { friends: target._id },
    });
    // Also remove from their friends list
    await User.findByIdAndUpdate(target._id, { $pull: { friends: req.user._id } });

    // Cancel any pending requests
    await FriendRequest.updateMany(
      {
        $or: [
          { sender: req.user._id, receiver: target._id },
          { sender: target._id, receiver: req.user._id },
        ],
        status: "pending",
      },
      { status: "cancelled" }
    );

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "USER_BLOCKED",
      targetType: "User",
      targetId: target._id,
      details: { blockedUsername: target.username },
    });

    res.json({ success: true, message: `${target.username} blocked` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Unblock user ───────────────────────────────────────────────────
exports.unblockUser = async (req, res) => {
  try {
    const { username } = req.body;
    const target = await User.findOne({ username: username?.toLowerCase() });
    if (!target) return res.status(404).json({ success: false, message: "User not found" });

    await User.findByIdAndUpdate(req.user._id, { $pull: { blockedUsers: target._id } });

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "USER_UNBLOCKED",
      targetType: "User",
      targetId: target._id,
    });

    res.json({ success: true, message: `${target.username} unblocked` });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Get pending requests ───────────────────────────────────────────
exports.getPendingRequests = async (req, res) => {
  try {
    const incoming = await FriendRequest.find({ receiver: req.user._id, status: "pending" })
      .populate("sender", "username displayName profilePicture")
      .sort({ createdAt: -1 });

    const outgoing = await FriendRequest.find({ sender: req.user._id, status: "pending" })
      .populate("receiver", "username displayName profilePicture")
      .sort({ createdAt: -1 });

    res.json({ success: true, data: { incoming, outgoing } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
