const crypto = require("crypto");
const User = require("../models/User.model");
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require("../utils/token.utils");
const { logAction } = require("../services/audit.service");
const { generateToken, sendActivationEmail } = require("../services/email.service");

// ── Signup ────────────────────────────────────────────────────────
exports.signup = async (req, res) => {
  try {
    const { username, email, password, displayName } = req.body;

    if (!username || !email || !password)
      return res.status(400).json({ success: false, message: "Username, email and password are required" });

    const existing = await User.findOne({ $or: [{ email: email.toLowerCase() }, { username: username.toLowerCase() }] });
    if (existing) return res.status(409).json({
      success: false,
      message: existing.email === email.toLowerCase() ? "Email already registered" : "Username already taken",
    });

    // Generate activation token — store only the hash in DB, send raw to user
    const activationToken     = generateToken();
    const activationTokenHash = crypto.createHash("sha256").update(activationToken).digest("hex");
    const activationExpires   = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

    const user = await User.create({
      username:    username.toLowerCase(),
      email:       email.toLowerCase(),
      password,
      displayName: displayName || username,
      isActive:       false,   // blocked until email confirmed
      emailVerified:  false,
      activationToken:        activationTokenHash,
      activationTokenExpires: activationExpires,
      forensicProfile: {
        registrationIp:        req.clientMeta?.ip,
        registrationDevice:    `${req.clientMeta?.device || ""} ${req.clientMeta?.deviceBrand || ""}`.trim(),
        registrationUserAgent: req.clientMeta?.userAgent,
        ipHistory: [{ ip: req.clientMeta?.ip, device: req.clientMeta?.device, os: req.clientMeta?.os, client: req.clientMeta?.client }],
      },
    });

    // Send activation email — non-blocking so a mail failure doesn't break signup
    try {
      await sendActivationEmail(email, displayName || username, activationToken);
    } catch (emailErr) {
      console.error("[signup] Email send failed:", emailErr.message);
    }

    await logAction({ req, actor: { userId: user._id, username: user.username }, action: "USER_SIGNUP", targetType: "User", targetId: user._id });

    res.status(201).json({
      success: true,
      message: `Account created! Check your inbox at ${email} and click the activation link before signing in.`,
      data: { email, requiresActivation: true },
    });
  } catch (err) {
    console.error("[signup]", err.message, err.stack);
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Activate Account  (GET /auth/activate?token=xxx) ─────────────
exports.activateAccount = async (req, res) => {
  try {
    const { token } = req.query;
    if (!token)
      return res.status(400).json({ success: false, message: "Activation token required" });

    const tokenHash = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      activationToken:        tokenHash,
      activationTokenExpires: { $gt: new Date() },
    });

    if (!user)
      return res.status(400).json({
        success: false,
        message: "Activation link is invalid or has expired. Please sign up again or request a new link.",
      });

    user.isActive             = true;
    user.emailVerified        = true;
    user.activationToken      = undefined;
    user.activationTokenExpires = undefined;

    // Issue tokens so user is logged in right after activation
    const accessToken  = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);
    if (!Array.isArray(user.refreshTokens)) user.refreshTokens = [];
    user.refreshTokens.push({ token: refreshToken, deviceInfo: req.clientMeta?.device, ipAddress: req.clientMeta?.ip });

    await user.save();

    await logAction({ req, actor: { userId: user._id, username: user.username }, action: "USER_ACTIVATED", targetType: "User", targetId: user._id });

    res.json({
      success: true,
      message: "Account activated! Welcome to ByteChat.",
      data: { user: user.toJSON(), accessToken, refreshToken },
    });
  } catch (err) {
    console.error("[activateAccount]", err.message, err.stack);
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Resend Activation Email ───────────────────────────────────────
exports.resendActivation = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email)
      return res.status(400).json({ success: false, message: "Email required" });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user)
      return res.status(404).json({ success: false, message: "No account found with this email" });
    if (user.isActive)
      return res.status(400).json({ success: false, message: "Account is already activated" });

    const activationToken     = generateToken();
    const activationTokenHash = crypto.createHash("sha256").update(activationToken).digest("hex");
    user.activationToken        = activationTokenHash;
    user.activationTokenExpires = new Date(Date.now() + 24 * 60 * 60 * 1000);
    await user.save();

    await sendActivationEmail(email, user.displayName || user.username, activationToken);

    res.json({ success: true, message: `Activation email resent to ${email}` });
  } catch (err) {
    console.error("[resendActivation]", err.message, err.stack);
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Login ─────────────────────────────────────────────────────────
exports.login = async (req, res) => {
  try {
    const { usernameOrEmail, password } = req.body;
    const user = await User.findOne({
      $or: [
        { email:    usernameOrEmail?.toLowerCase() },
        { username: usernameOrEmail?.toLowerCase() },
      ],
    }).select("+password +refreshTokens");

    if (!user || !(await user.comparePassword(password)))
      return res.status(401).json({ success: false, message: "Invalid credentials" });

    // Block login if email not verified yet
    if (!user.emailVerified || !user.isActive) {
      return res.status(403).json({
        success: false,
        requiresActivation: true,
        email: user.email,
        message: "Please activate your account first. Check your email for the activation link.",
      });
    }

    const accessToken  = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    if (!Array.isArray(user.refreshTokens)) user.refreshTokens = [];
    if (user.refreshTokens.length >= 5) user.refreshTokens.shift();
    user.refreshTokens.push({ token: refreshToken, deviceInfo: req.clientMeta?.device, ipAddress: req.clientMeta?.ip });
    user.lastSeen = new Date();

    if (!user.forensicProfile) user.forensicProfile = {};
    user.forensicProfile.lastLoginIp     = req.clientMeta?.ip;
    user.forensicProfile.lastLoginDevice = req.clientMeta?.device;
    user.forensicProfile.lastLoginAt     = new Date();
    if (!Array.isArray(user.forensicProfile.ipHistory)) user.forensicProfile.ipHistory = [];
    user.forensicProfile.ipHistory.push({ ip: req.clientMeta?.ip, device: req.clientMeta?.device, os: req.clientMeta?.os, client: req.clientMeta?.client });
    if (user.forensicProfile.ipHistory.length > 50) user.forensicProfile.ipHistory.shift();

    await user.save();

    await logAction({ req, actor: { userId: user._id, username: user.username }, action: "USER_LOGIN", targetType: "User", targetId: user._id, details: { ip: req.clientMeta?.ip, device: req.clientMeta?.device } });

    res.json({ success: true, message: "Logged in successfully", data: { user: user.toJSON(), accessToken, refreshToken } });
  } catch (err) {
    console.error("[login]", err.message, err.stack);
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Refresh Token ─────────────────────────────────────────────────
exports.refreshToken = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken)
      return res.status(400).json({ success: false, message: "Refresh token required" });

    let decoded;
    try {
      decoded = verifyRefreshToken(refreshToken);
    } catch (jwtErr) {
      return res.status(401).json({ success: false, message: "Invalid or expired refresh token — please sign in again" });
    }

    const userId = decoded.id || decoded.userId || decoded._id;
    if (!userId)
      return res.status(401).json({ success: false, message: "Malformed token — please sign in again" });

    const user = await User.findById(userId).select("+refreshTokens");
    if (!user)
      return res.status(401).json({ success: false, message: "User not found" });
    if (!user.isActive)
      return res.status(403).json({ success: false, message: "Account is deactivated" });

    if (!Array.isArray(user.refreshTokens))
      return res.status(401).json({ success: false, message: "Session data missing — please sign in again" });

    const tokenEntry = user.refreshTokens.find(t => t.token === refreshToken);
    if (!tokenEntry)
      return res.status(401).json({ success: false, message: "Session expired — please sign in again" });

    user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
    const newAccessToken  = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);
    if (user.refreshTokens.length >= 5) user.refreshTokens.shift();
    user.refreshTokens.push({ token: newRefreshToken, deviceInfo: req.clientMeta?.device, ipAddress: req.clientMeta?.ip });
    await user.save();

    res.json({ success: true, data: { accessToken: newAccessToken, refreshToken: newRefreshToken } });
  } catch (err) {
    console.error("[refreshToken] Unexpected error:", err.message, err.stack);
    res.status(500).json({ success: false, message: "Token refresh failed — please sign in again" });
  }
};

// ── Logout ────────────────────────────────────────────────────────
exports.logout = async (req, res) => {
  try {
    const { refreshToken } = req.body;
    if (!req.user?._id)
      return res.json({ success: true, message: "Logged out" });

    const user = await User.findById(req.user._id).select("+refreshTokens");
    if (user) {
      if (!Array.isArray(user.refreshTokens)) user.refreshTokens = [];
      if (refreshToken) user.refreshTokens = user.refreshTokens.filter(t => t.token !== refreshToken);
      await user.save();
      await logAction({ req, actor: { userId: user._id, username: user.username }, action: "USER_LOGOUT", targetType: "User", targetId: user._id });
    }
    res.json({ success: true, message: "Logged out successfully" });
  } catch (err) {
    console.error("[logout] error:", err.message);
    res.json({ success: true, message: "Logged out" });
  }
};