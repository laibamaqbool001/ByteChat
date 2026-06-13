const mongoose = require("mongoose");

const auditLogSchema = new mongoose.Schema(
  {
    // Who performed the action
    actor: {
      userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
      username: String,
      ip: String,
      device: String,
    },
    // What action was performed
    action: {
      type: String,
      required: true,
      enum: [
        // Auth
        "USER_SIGNUP", "USER_LOGIN", "USER_LOGOUT", "TOKEN_REFRESH",
        "PASSWORD_CHANGE",
        // Social
        "FRIEND_REQUEST_SENT", "FRIEND_REQUEST_ACCEPTED",
        "FRIEND_REQUEST_DECLINED", "FRIEND_REQUEST_CANCELLED",
        "FRIEND_REMOVED", "USER_BLOCKED", "USER_UNBLOCKED",
        // Messages
        "MESSAGE_SENT", "MESSAGE_READ", "MESSAGE_DELETED", "MESSAGE_EDITED",
        // Forensic
        "EVIDENCE_EXPORTED", "CHAIN_OF_CUSTODY_ACCESSED",
        "TAMPER_DETECTED", "METADATA_CONSENT_GIVEN",
        "METADATA_CONSENT_REVOKED", "FORENSIC_REPORT_GENERATED",
        // Profile
        "PROFILE_UPDATED", "PROFILE_PICTURE_UPDATED",
      ],
    },
    // The subject of the action (message, user, etc.)
    targetType: {
      type: String,
      enum: ["User", "Message", "FriendRequest", "EvidenceReport", "System"],
    },
    targetId: mongoose.Schema.Types.ObjectId,
    // Additional structured data about the event
    details: { type: mongoose.Schema.Types.Mixed },
    // Integrity hash of this log entry itself (prevents log tampering)
    entryHash: { type: String },
    timestamp: { type: Date, default: Date.now, immutable: true },
  },
  { timestamps: false }
);

// Prevent deletion of audit logs (append-only)
auditLogSchema.pre("remove", function (next) {
  const err = new Error("Audit logs cannot be deleted");
  err.status = 403;
  next(err);
});

auditLogSchema.index({ "actor.userId": 1, timestamp: -1 });
auditLogSchema.index({ targetId: 1, action: 1 });

module.exports = mongoose.model("AuditLog", auditLogSchema);
