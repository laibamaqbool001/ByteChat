const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, "Username is required"],
      unique: true,
      trim: true,
      lowercase: true,
      minlength: [3, "Username must be at least 3 characters"],
      maxlength: [30, "Username cannot exceed 30 characters"],
      match: [/^[a-zA-Z0-9._]+$/, "Username can only contain letters, numbers, dots, and underscores"],
    },
    email: {
      type: String,
      required: [true, "Email is required"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\S+@\S+\.\S+$/, "Invalid email format"],
    },
    password: {
      type: String,
      required: [true, "Password is required"],
      minlength: [8, "Password must be at least 8 characters"],
      select: false,
    },
    displayName: { type: String, trim: true, maxlength: 50 },
    bio:         { type: String, maxlength: 150 },
    profilePicture: {
      url:      { type: String, default: "" },
      publicId: { type: String, default: "" },
    },

    // ── Friend system ──────────────────────────────────────────────
    friends:      [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],
    blockedUsers: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    // ── Auth ───────────────────────────────────────────────────────
    refreshTokens: [
      {
        token:      String,
        createdAt:  { type: Date, default: Date.now },
        deviceInfo: String,
        ipAddress:  String,
      },
    ],

    // Account status — false until email is verified
    isActive:      { type: Boolean, default: false },
    lastSeen:      { type: Date, default: Date.now },

    // ── Email verification ─────────────────────────────────────────
    emailVerified:          { type: Boolean, default: false },
    activationToken:        { type: String,  select: false }, // stored as SHA-256 hash
    activationTokenExpires: { type: Date,    select: false },

    // ── Forensic metadata — captured silently on every login/action ─
    forensicProfile: {
      registrationIp:        String,
      registrationDevice:    String,
      registrationUserAgent: String,
      lastLoginIp:           String,
      lastLoginDevice:       String,
      lastLoginAt:           Date,
      ipHistory: [
        {
          ip:     String,
          device: String,
          os:     String,
          client: String,
          seenAt: { type: Date, default: Date.now },
        },
      ],
    },
  },
  { timestamps: true }
);

// ── Indexes ────────────────────────────────────────────────────────
userSchema.index({ activationToken: 1 }); // fast token lookup during activation

// ── Hash password before save ──────────────────────────────────────
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

// Strip all sensitive data from client responses
userSchema.methods.toJSON = function () {
  const obj = this.toObject();
  delete obj.password;
  delete obj.refreshTokens;
  delete obj.blockedUsers;
  delete obj.forensicProfile;
  delete obj.activationToken;        // never expose token to client
  delete obj.activationTokenExpires;
  return obj;
};

module.exports = mongoose.model("User", userSchema);
