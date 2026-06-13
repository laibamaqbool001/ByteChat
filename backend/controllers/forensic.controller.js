const path = require("path");
const fs = require("fs");
const AuditLog = require("../models/AuditLog.model");
const EvidenceReport = require("../models/EvidenceReport.model");
const Message = require("../models/Message.model");
const User = require("../models/User.model");
const { generateEvidenceReport } = require("../services/evidence.service");
const { verifyMessageHash, verifyEvidenceSignature } = require("../utils/hash.utils");
const { decrypt } = require("../utils/encryption.utils");
const { logAction, getChainOfCustody, getUserActivityLog } = require("../services/audit.service");

// ── Generate evidence report ───────────────────────────────────────
exports.generateReport = async (req, res) => {
  try {
    const { targetUsername, startDate, endDate, includeMetadata = false } = req.body;

    if (!targetUsername || !startDate || !endDate) {
      return res.status(400).json({ success: false, message: "targetUsername, startDate, endDate required" });
    }

    const targetUser = await User.findOne({ username: targetUsername.toLowerCase() });
    if (!targetUser) return res.status(404).json({ success: false, message: "Target user not found" });

    const { reportId, report, summary } = await generateEvidenceReport({
      requestedById: req.user._id,
      userIds: [req.user._id, targetUser._id],
      startDate,
      endDate,
      includedData: {
        messages: true,
        auditLogs: true,
        metadata: includeMetadata && req.user.forensicConsent?.metadataCapture,
        accessLogs: true,
      },
      req,
    });

    res.json({
      success: true,
      message: "Evidence report generated",
      data: { reportId, summary, downloadUrl: `/api/forensics/reports/${reportId}/download` },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Download generated report ──────────────────────────────────────
exports.downloadReport = async (req, res) => {
  try {
    const report = await EvidenceReport.findOne({ reportId: req.params.reportId });
    if (!report) return res.status(404).json({ success: false, message: "Report not found" });

    if (!report.requestedBy.equals(req.user._id)) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    if (report.status === "expired" || new Date() > report.expiresAt) {
      return res.status(410).json({ success: false, message: "Report has expired" });
    }

    if (!fs.existsSync(report.filePath)) {
      return res.status(404).json({ success: false, message: "Report file not found" });
    }

    // Update chain of custody
    report.custodyChain.push({
      action: "downloaded",
      by: req.user._id,
      at: new Date(),
      ip: req.clientMeta?.ip,
    });
    await report.save();

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "EVIDENCE_EXPORTED",
      targetType: "EvidenceReport",
      targetId: report._id,
      details: { reportId: report.reportId },
    });

    res.download(report.filePath, `bytechat-evidence-${report.reportId}.pdf`);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Download JSON version of report ──────────────────────────────
exports.downloadReportJSON = async (req, res) => {
  try {
    const report = await EvidenceReport.findOne({ reportId: req.params.reportId });
    if (!report) return res.status(404).json({ success: false, message: "Report not found" });
    if (!report.requestedBy.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Access denied" });

    const jsonPath = report.filePath.replace(".pdf", ".json");
    if (!fs.existsSync(jsonPath)) return res.status(404).json({ success: false, message: "JSON report not found" });

    report.custodyChain.push({ action: "downloaded", by: req.user._id, at: new Date(), ip: req.clientMeta?.ip });
    await report.save();

    res.download(jsonPath, `bytechat-evidence-${report.reportId}.json`);
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Verify report integrity ────────────────────────────────────────
exports.verifyReport = async (req, res) => {
  try {
    const report = await EvidenceReport.findOne({ reportId: req.params.reportId });
    if (!report) return res.status(404).json({ success: false, message: "Report not found" });

    const valid = verifyEvidenceSignature(
      report.reportId,
      report.reportHash,
      report.createdAt.toISOString(),
      report.digitalSignature
    );

    res.json({
      success: true,
      data: {
        reportId: report.reportId,
        signatureValid: valid,
        reportHash: report.reportHash,
        generatedAt: report.createdAt,
        status: valid ? "Report integrity verified — not tampered" : "⚠ Report signature invalid — possible tampering",
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Get chain of custody for a message ────────────────────────────
exports.getMessageCustody = async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId)
      .populate("sender", "username")
      .populate("receiver", "username")
      .populate("accessLog.accessedBy", "username");

    if (!message) return res.status(404).json({ success: false, message: "Message not found" });

    if (!message.sender._id.equals(req.user._id) && !message.receiver._id.equals(req.user._id)) {
      return res.status(403).json({ success: false, message: "Access denied" });
    }

    const custody = await getChainOfCustody(message._id, "Message");

    await logAction({
      req,
      actor: { userId: req.user._id, username: req.user.username },
      action: "CHAIN_OF_CUSTODY_ACCESSED",
      targetType: "Message",
      targetId: message._id,
    });

    res.json({
      success: true,
      data: {
        message: {
          id: message._id,
          sender: message.sender?.username,
          receiver: message.receiver?.username,
          sentAt: message.sentAt,
          contentHash: message.contentHash,
          editHistory: message.editHistory,
          accessLog: message.accessLog,
        },
        custodyLog: custody,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Get user activity log ──────────────────────────────────────────
exports.getMyActivityLog = async (req, res) => {
  try {
    const { page = 1, limit = 50 } = req.query;
    const logs = await getUserActivityLog(req.user._id, { page: Number(page), limit: Number(limit) });
    res.json({ success: true, data: logs });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Batch tamper check on conversation ────────────────────────────
exports.verifyConversationIntegrity = async (req, res) => {
  try {
    const { username } = req.params;
    const otherUser = await User.findOne({ username: username.toLowerCase() });
    if (!otherUser) return res.status(404).json({ success: false, message: "User not found" });

    const messages = await Message.find({
      $or: [
        { sender: req.user._id, receiver: otherUser._id },
        { sender: otherUser._id, receiver: req.user._id },
      ],
    }).sort({ sentAt: 1 });

    let intactCount = 0;
    let tamperedMessages = [];

    for (const msg of messages) {
      let plaintext = null;
      let gcmAuthPassed = true;
      try {
        plaintext = decrypt({
          ciphertext: msg.content,
          iv: msg.encryptionMeta?.iv,
          authTag: msg.encryptionMeta?.authTag,
          keyVersion: msg.encryptionMeta?.keyVersion,
        });
      } catch {
        gcmAuthPassed = false;
      }

      const result = gcmAuthPassed
        ? verifyMessageHash(msg, plaintext)
        : { intact: false, expected: null, stored: msg.contentHash };

      const intact = gcmAuthPassed && result.intact;

      if (intact) {
        intactCount++;
      } else {
        tamperedMessages.push({
          id: msg._id,
          sentAt: msg.sentAt,
          gcmAuthenticationPassed: gcmAuthPassed,
          hmacIntact: result.intact,
          storedHash: result.stored,
        });

        await logAction({
          req,
          actor: { userId: req.user._id, username: req.user.username },
          action: "TAMPER_DETECTED",
          targetType: "Message",
          targetId: msg._id,
          details: result,
        });
      }
    }

    res.json({
      success: true,
      data: {
        total: messages.length,
        intact: intactCount,
        tampered: tamperedMessages.length,
        tamperedMessages,
        allIntact: tamperedMessages.length === 0,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── List my reports ───────────────────────────────────────────────
exports.listMyReports = async (req, res) => {
  try {
    const reports = await EvidenceReport.find({ requestedBy: req.user._id })
      .select("reportId status createdAt expiresAt dateRangeStart dateRangeEnd summary")
      .sort({ createdAt: -1 });

    res.json({ success: true, data: reports });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
