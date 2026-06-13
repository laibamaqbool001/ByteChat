const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    sender:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },

    // Always ciphertext in DB — decrypted before sending to client
    content: { type: String, required: true, maxlength: [20000, "Message too long"] },

    messageType: { type: String, enum: ["text", "image", "file"], default: "text" },

    // Image attachment (when messageType = "image")
    attachment: {
      url:      String,
      publicId: String,
      width:    Number,
      height:   Number,
      format:   String,
    },

    // ── AES-256-GCM encryption envelope ──────────────────────────
    encryptionMeta: {
      iv:         { type: String, required: true },
      authTag:    { type: String, required: true },
      keyVersion: { type: Number, default: 1 },
      algorithm:  { type: String, default: "AES-256-GCM" },
    },

    isDeleted: { type: Boolean, default: false },
    deletedAt: Date,

    // ── Forensic: message tamper detection ────────────────────────
    contentHash: { type: String, required: true },
    editHistory: [
      {
        previousContent: { ciphertext: String, iv: String, authTag: String, keyVersion: Number },
        previousHash:    String,
        editedAt:        { type: Date, default: Date.now },
        editedByIp:      String,
      },
    ],

    // ── Forensic: image replacement history ───────────────────────
    // Each entry records the previous attachment + forensics snapshot
    // when the sender replaced the image via editImage().
    // Mirrors editHistory but for image messages specifically.
    imageEditHistory: [
      {
        // The old Cloudinary attachment details
        previousAttachment: {
          url:      String,
          publicId: String,
          width:    Number,
          height:   Number,
          format:   String,
        },
        // Server-side SHA-256 of the replaced image buffer
        previousServerHash: String,
        // Client-supplied SHA-256 of the replaced image (if provided)
        previousClientHash: String,
        // New image hashes after replacement
        newServerHash:  String,
        newClientHash:  String,
        // Integrity flag for the *new* upload
        newUploadIntegrityMatch: { type: Boolean, default: null },
        editedAt:      { type: Date, default: Date.now },
        editedByIp:    String,
        editedDevice:  String,
      },
    ],

    // ── Forensic: traceability ────────────────────────────────────
    sentAt:          { type: Date, default: Date.now },
    deliveredAt:     Date,
    readAt:          Date,
    senderSignature: String,

    // ── Forensic: metadata (always captured silently) ─────────────
    metadata: {
      senderIp:        String,
      senderDevice:    String,
      senderOs:        String,
      senderClient:    String,
      senderUserAgent: String,
    },

    // ── Forensic: image authenticity ──────────────────────────────
    imageForensics: {
      clientHash:           String,
      serverHash:           String,
      uploadIntegrityMatch: { type: Boolean, default: null },
      uploadedAt:           Date,
      uploaderIp:           String,
      uploaderDevice:       String,
    },

    // ── Forensic: chain of custody access log ─────────────────────
    accessLog: [
      {
        accessedBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
        accessedAt: { type: Date, default: Date.now },
        action:     { type: String, enum: ["read", "export", "admin_view", "evidence_access"] },
        accessIp:   String,
      },
    ],
  },
  { timestamps: true }
);

messageSchema.index({ sender: 1, receiver: 1, sentAt: -1 });

module.exports = mongoose.model("Message", messageSchema);