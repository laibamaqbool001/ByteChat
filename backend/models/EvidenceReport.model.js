const mongoose = require("mongoose");

const evidenceReportSchema = new mongoose.Schema(
  {
    reportId: { type: String, required: true, unique: true },
    requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    targetUser: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
    conversationBetween: [{ type: mongoose.Schema.Types.ObjectId, ref: "User" }],

    dateRangeStart: Date,
    dateRangeEnd: Date,

    includedData: {
      messages:   { type: Boolean, default: true },
      auditLogs:  { type: Boolean, default: true },
      metadata:   { type: Boolean, default: false },
      accessLogs: { type: Boolean, default: true },
    },

    // ── Summary stored directly in DB ─────────────────────────────
    summary: {
      totalMessages:    { type: Number, default: 0 },
      tamperedMessages: { type: Number, default: 0 },
      deletedMessages:  { type: Number, default: 0 },
      editedMessages:   { type: Number, default: 0 },
      imageMessages:    { type: Number, default: 0 },
      integrityRate:    { type: String, default: "100%" },
    },

    // ── Full report data stored in DB (no file dependency) ────────
    reportData: { type: mongoose.Schema.Types.Mixed },

    // ── Report integrity ──────────────────────────────────────────
    reportHash:       String,
    digitalSignature: String,

    // ── Chain of custody ──────────────────────────────────────────
    custodyChain: [
      {
        action: { type: String, enum: ["created", "accessed", "downloaded", "shared"] },
        by:     { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        at:     { type: Date, default: Date.now },
        ip:     String,
        notes:  String,
      },
    ],

    status:    { type: String, enum: ["pending", "generated", "expired"], default: "pending" },
    expiresAt: Date,
    filePath:  String, // optional PDF path if pdfkit is installed
  },
  { timestamps: true }
);

evidenceReportSchema.index({ requestedBy: 1, createdAt: -1 });
evidenceReportSchema.index({ reportId: 1 });

module.exports = mongoose.model("EvidenceReport", evidenceReportSchema);