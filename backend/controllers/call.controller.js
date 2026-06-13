const Call = require("../models/Call.model");
const User = require("../models/User.model");
const { logAction } = require("../services/audit.service");

// ── Initiate call ─────────────────────────────────────────────────
exports.initiateCall = async (req, res) => {
  try {
    const { receiverUsername, callType } = req.body;
    if (!["voice", "video"].includes(callType))
      return res.status(400).json({ success: false, message: "callType must be 'voice' or 'video'" });

    const receiver = await User.findOne({ username: receiverUsername?.toLowerCase(), isActive: true });
    if (!receiver) return res.status(404).json({ success: false, message: "User not found" });

    const caller = await User.findById(req.user._id).select("friends");
    if (!caller.friends.map(String).includes(String(receiver._id)))
      return res.status(403).json({ success: false, message: "You can only call friends" });

    const call = await Call.create({
      caller: req.user._id,
      receiver: receiver._id,
      callType,
      status: "ringing",
      forensics: { callerIp: req.clientMeta?.ip, callerDevice: req.clientMeta?.device },
    });

    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_SENT", targetType: "Message", targetId: call._id, details: { callType, receiverUsername } });

    res.status(201).json({ success: true, data: call });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Update call status ────────────────────────────────────────────
exports.updateCallStatus = async (req, res) => {
  try {
    const { status } = req.body;
    const call = await Call.findById(req.params.callId);
    if (!call) return res.status(404).json({ success: false, message: "Call not found" });

    const isParty = call.caller.equals(req.user._id) || call.receiver.equals(req.user._id);
    if (!isParty) return res.status(403).json({ success: false, message: "Access denied" });

    call.status = status;
    if (status === "accepted") call.startedAt = new Date();
    if (["ended", "declined", "missed"].includes(status)) {
      call.endedAt = new Date();
      if (call.startedAt) call.duration = Math.round((call.endedAt - call.startedAt) / 1000);
    }
    await call.save();

    res.json({ success: true, data: call });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Get call history ──────────────────────────────────────────────
exports.getCallHistory = async (req, res) => {
  try {
    const calls = await Call.find({
      $or: [{ caller: req.user._id }, { receiver: req.user._id }],
    })
      .populate("caller", "username displayName profilePicture")
      .populate("receiver", "username displayName profilePicture")
      .sort({ createdAt: -1 })
      .limit(50);

    // Strip forensic data before sending to client
    const cleaned = calls.map(c => {
      const obj = c.toObject();
      delete obj.forensics;
      return obj;
    });

    res.json({ success: true, data: cleaned });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};