const mongoose = require("mongoose");

const callSchema = new mongoose.Schema(
  {
    caller: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    receiver: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    callType: { type: String, enum: ["voice", "video"], required: true },
    status: {
      type: String,
      enum: ["initiated", "ringing", "accepted", "declined", "missed", "ended"],
      default: "initiated",
    },
    startedAt: Date,   // when receiver accepted
    endedAt: Date,
    duration: Number,  // seconds

    // Forensic: always captured silently
    forensics: {
      callerIp: String,
      callerDevice: String,
      receiverIp: String,
      initiatedAt: { type: Date, default: Date.now },
    },
  },
  { timestamps: true }
);

callSchema.index({ caller: 1, receiver: 1, createdAt: -1 });

module.exports = mongoose.model("Call", callSchema);