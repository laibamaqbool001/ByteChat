const { v4: uuidv4 } = require("uuid");
const path  = require("path");
const fs    = require("fs");
const Message      = require("../models/Message.model");
const AuditLog     = require("../models/AuditLog.model");
const EvidenceReport = require("../models/EvidenceReport.model");
const { computeObjectHash, signEvidenceReport, verifyMessageHash } = require("../utils/hash.utils");
const { decrypt } = require("../utils/encryption.utils");
const { logAction } = require("./audit.service");

// ── Optional PDF support ──────────────────────────────────────────
// pdfkit is optional — report is always saved fully to MongoDB.
// If pdfkit is installed (npm install pdfkit) a PDF file is also written.
let PDFDocument = null;
try { PDFDocument = require("pdfkit"); } catch { /* PDF generation skipped */ }

const REPORTS_DIR = path.join(__dirname, "../reports");
if (!fs.existsSync(REPORTS_DIR)) fs.mkdirSync(REPORTS_DIR, { recursive: true });

/**
 * Generate a forensic evidence report and save it to MongoDB.
 *
 * Everything is stored in the EvidenceReport document:
 *   - summary  (counts, integrity rate)
 *   - reportData (full decrypted messages + audit logs)
 *   - reportHash + digitalSignature (tamper-proof)
 *   - custodyChain
 *
 * A PDF + JSON file are also written to /reports/ if pdfkit is available.
 */
const generateEvidenceReport = async ({
  requestedById,
  userIds,
  startDate,
  endDate,
  includedData,
  req,
}) => {
  const reportId    = uuidv4();
  const generatedAt = new Date();

  // ── 1. Fetch messages ─────────────────────────────────────────
  const messages = await Message.find({
    $or: [
      { sender: userIds[0], receiver: userIds[1] },
      { sender: userIds[1], receiver: userIds[0] },
    ],
    sentAt: { $gte: new Date(startDate), $lte: new Date(endDate) },
  })
    .populate("sender",   "username email")
    .populate("receiver", "username email")
    .sort({ sentAt: 1 });

  // ── 2. Decrypt + tamper-check every message ───────────────────
  const messagesWithIntegrity = messages.map((msg) => {
    let plaintext      = "[decryption failed]";
    let gcmAuthPassed  = true;

    try {
      plaintext = decrypt({
        ciphertext: msg.content,
        iv:         msg.encryptionMeta?.iv,
        authTag:    msg.encryptionMeta?.authTag,
        keyVersion: msg.encryptionMeta?.keyVersion,
      });
    } catch {
      gcmAuthPassed = false;
    }

    const integrity = gcmAuthPassed
      ? verifyMessageHash(msg, plaintext)
      : { intact: false, expected: null, stored: msg.contentHash };

    return {
      id:          msg._id,
      sender:      msg.sender?.username,
      receiver:    msg.receiver?.username,
      content:     msg.messageType === "image" ? msg.attachment?.url || "[image]" : plaintext,
      sentAt:      msg.sentAt,
      deliveredAt: msg.deliveredAt,
      readAt:      msg.readAt,
      messageType: msg.messageType,
      isDeleted:   msg.isDeleted,
      editCount:   msg.editHistory?.length || 0,
      imageEditCount: msg.imageEditHistory?.length || 0,
      integrity: {
        intact:                  gcmAuthPassed && integrity.intact,
        gcmAuthenticationPassed: gcmAuthPassed,
        hmacHashIntact:          integrity.intact,
        storedHash:              integrity.stored,
        encryptionAlgorithm:     "AES-256-GCM",
        keyVersion:              msg.encryptionMeta?.keyVersion,
      },
      // Image forensics if present
      imageForensics: msg.messageType === "image" ? {
        serverHash:           msg.imageForensics?.serverHash,
        uploadIntegrityMatch: msg.imageForensics?.uploadIntegrityMatch,
        uploadedAt:           msg.imageForensics?.uploadedAt,
        editHistory:          (msg.imageEditHistory || []).map(e => ({
          editedAt:           e.editedAt,
          previousServerHash: e.previousServerHash,
          newServerHash:      e.newServerHash,
        })),
      } : undefined,
    };
  });

  // ── 3. Fetch audit logs ───────────────────────────────────────
  let auditLogs = [];
  if (includedData?.auditLogs) {
    auditLogs = await AuditLog.find({
      "actor.userId": { $in: userIds },
      timestamp: { $gte: new Date(startDate), $lte: new Date(endDate) },
    }).sort({ timestamp: 1 });
  }

  // ── 4. Build summary ──────────────────────────────────────────
  const tamperedCount = messagesWithIntegrity.filter(m => !m.integrity.intact).length;
  const integrityRate = messages.length > 0
    ? `${(((messages.length - tamperedCount) / messages.length) * 100).toFixed(1)}%`
    : "N/A";

  const summary = {
    totalMessages:    messages.length,
    tamperedMessages: tamperedCount,
    deletedMessages:  messagesWithIntegrity.filter(m => m.isDeleted).length,
    editedMessages:   messagesWithIntegrity.filter(m => m.editCount > 0).length,
    imageMessages:    messagesWithIntegrity.filter(m => m.messageType === "image").length,
    integrityRate,
  };

  // ── 5. Build full report object ───────────────────────────────
  const reportData = {
    reportId,
    generatedAt:  generatedAt.toISOString(),
    generatedBy:  requestedById,
    dateRange:    { start: startDate, end: endDate },
    subjects:     userIds,
    summary,
    messages:     messagesWithIntegrity,
    auditLogs:    auditLogs.map(log => ({
      action:     log.action,
      actor:      log.actor,
      targetType: log.targetType,
      targetId:   log.targetId,
      timestamp:  log.timestamp,
      entryHash:  log.entryHash,
    })),
  };

  // ── 6. Hash and sign the report ───────────────────────────────
  const reportHash       = computeObjectHash(reportData);
  const digitalSignature = signEvidenceReport(reportId, reportHash, generatedAt.toISOString());
  reportData.integrity   = { reportHash, digitalSignature };

  // ── 7. Save JSON file (optional but useful) ───────────────────
  const jsonPath = path.join(REPORTS_DIR, `${reportId}.json`);
  try {
    fs.writeFileSync(jsonPath, JSON.stringify(reportData, null, 2));
  } catch (e) {
    console.warn("[evidence] JSON write failed:", e.message);
  }

  // ── 8. Generate PDF (only if pdfkit installed) ────────────────
  let pdfPath = null;
  if (PDFDocument) {
    pdfPath = path.join(REPORTS_DIR, `${reportId}.pdf`);
    try {
      await generatePDFReport(reportData, pdfPath);
    } catch (e) {
      console.warn("[evidence] PDF generation failed:", e.message);
      pdfPath = null;
    }
  }

  // ── 9. Save to MongoDB ────────────────────────────────────────
  // This is the PRIMARY storage — everything is in the DB document.
  // Files are secondary/optional.
  const report = await EvidenceReport.create({
    reportId,
    requestedBy:         requestedById,
    conversationBetween: userIds,
    dateRangeStart:      startDate,
    dateRangeEnd:        endDate,
    includedData,
    summary,                    // summary stored directly → visible in Atlas
    reportData,                 // full report stored → queryable in Atlas
    reportHash,
    digitalSignature,
    custodyChain: [{
      action: "created",
      by:     requestedById,
      at:     generatedAt,
      ip:     req?.clientMeta?.ip || "unknown",
      notes:  "Initial generation",
    }],
    status:    "generated",
    expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days
    filePath:  pdfPath || jsonPath,
  });

  // ── 10. Audit log the generation ──────────────────────────────
  await logAction({
    req,
    actor:      { userId: requestedById },
    action:     "FORENSIC_REPORT_GENERATED",
    targetType: "EvidenceReport",
    targetId:   report._id,
    details:    { reportId, messageCount: messages.length, tamperedCount },
  });

  return { reportId, report, jsonPath, pdfPath, summary };
};

// ── PDF Generator (used only if pdfkit installed) ─────────────────
const generatePDFReport = (reportData, outputPath) => {
  return new Promise((resolve, reject) => {
    const doc    = new PDFDocument({ margin: 50 });
    const stream = fs.createWriteStream(outputPath);
    doc.pipe(stream);

    // ── Header ──
    doc.fontSize(20).font("Helvetica-Bold")
       .text("ByteChat — Forensic Evidence Report", { align: "center" });
    doc.moveDown();
    doc.fontSize(10).font("Helvetica")
       .text(`Report ID   : ${reportData.reportId}`)
       .text(`Generated   : ${new Date(reportData.generatedAt).toUTCString()}`)
       .text(`Date Range  : ${reportData.dateRange.start}  →  ${reportData.dateRange.end}`);
    doc.moveDown();

    // ── Integrity ──
    doc.fontSize(12).font("Helvetica-Bold").text("Report Integrity");
    doc.fontSize(8).font("Courier")
       .text(`Hash      : ${reportData.integrity.reportHash}`)
       .text(`Signature : ${reportData.integrity.digitalSignature}`);
    doc.moveDown();

    // ── Summary ──
    const s = reportData.summary;
    doc.fontSize(12).font("Helvetica-Bold").text("Summary");
    doc.fontSize(10).font("Helvetica")
       .text(`Total Messages    : ${s.totalMessages}`)
       .text(`Tampered          : ${s.tamperedMessages}`)
       .text(`Deleted           : ${s.deletedMessages}`)
       .text(`Edited            : ${s.editedMessages}`)
       .text(`Image Messages    : ${s.imageMessages}`)
       .text(`Integrity Rate    : ${s.integrityRate}`);
    doc.moveDown();

    // ── Messages ──
    doc.fontSize(12).font("Helvetica-Bold").text("Message Log");
    doc.moveDown(0.4);
    reportData.messages.forEach((msg, i) => {
      doc.fontSize(9).font("Helvetica-Bold")
         .text(`[${i + 1}] ${msg.sender} → ${msg.receiver}  |  ${new Date(msg.sentAt).toUTCString()}`);
      doc.font("Helvetica")
         .text(`Content   : ${msg.content}`)
         .text(`Integrity : ${msg.integrity.intact ? "✓ INTACT" : "⚠ TAMPERED"}  |  Hash: ${msg.integrity.storedHash || "N/A"}`);
      if (msg.editCount > 0)      doc.text(`Edits     : ${msg.editCount}`);
      if (msg.imageEditCount > 0) doc.text(`Img Edits : ${msg.imageEditCount}`);
      if (msg.isDeleted)          doc.text(`Status    : DELETED`);
      doc.moveDown(0.3);
    });

    // ── Audit logs ──
    if (reportData.auditLogs.length > 0) {
      doc.addPage();
      doc.fontSize(12).font("Helvetica-Bold").text("Audit / Chain of Custody Log");
      doc.moveDown(0.4);
      reportData.auditLogs.forEach(log => {
        doc.fontSize(8).font("Helvetica")
           .text(`${new Date(log.timestamp).toUTCString()}  |  ${log.action}  |  by ${log.actor?.username || "system"}`);
      });
    }

    doc.end();
    stream.on("finish", resolve);
    stream.on("error", reject);
  });
};

module.exports = { generateEvidenceReport };