const crypto = require("crypto");
const Message = require("../models/Message.model");
const User = require("../models/User.model");
const { computeMessageHash, verifyMessageHash } = require("../utils/hash.utils");
const { encrypt, decrypt } = require("../utils/encryption.utils");
const { generateMessageSignature } = require("../utils/token.utils");
const { getMetadata } = require("../middleware/metadata.middleware");
const { logAction } = require("../services/audit.service");
const { uploadToCloudinary, cloudinary } = require("../config/cloudinary");

// ═══════════════════════════════════════════════════════════════════
//  TAMPER DETECTION — FOUR LAYERS
//
//  Layer 1  Transit integrity (images)
//    Browser SHA-256s the raw File bytes BEFORE sending.
//    Server SHA-256s the received buffer.
//    Mismatch → image altered between browser and server (MITM / proxy).
//    Stored as imageForensics.uploadIntegrityMatch = false.
//    Logged as TAMPER_DETECTED { layer: "transit" }.
//
//  Layer 2  Storage integrity (all messages, passive)
//    Before encryption, HMAC-SHA256 of plaintext stored as contentHash.
//    On every getConversation call, server re-decrypts and re-hashes.
//    Mismatch → DB record edited outside the application.
//    Client receives tampered: true on that message object.
//    Logged as TAMPER_DETECTED { layer: "storage" }.
//
//  Layer 3  Image authenticity (on-demand, POST /:id/verify-image)
//    Either party uploads a copy of the image they have.
//    Server hashes it and compares against stored serverHash.
//    Mismatch → copy was edited after original send
//    (crop / annotate / filter / re-save / screenshot).
//    Logged as TAMPER_DETECTED { layer: "post_send" }.
//
//  Layer 4  Text integrity (on-demand, GET /:id/verify-text)
//    Either party requests explicit hash check of a text message.
//    Server re-decrypts, re-hashes, compares against contentHash.
//    Mismatch → ciphertext or hash corrupted / modified in DB.
//    Logged as TAMPER_DETECTED { layer: "storage" }.
// ═══════════════════════════════════════════════════════════════════


// ── Helpers ───────────────────────────────────────────────────────

/** SHA-256 a raw buffer → hex string */
const hashBuffer = (buf) =>
  crypto.createHash("sha256").update(buf).digest("hex");

/**
 * Decrypt a message document → client-safe plain object.
 *
 * When checkIntegrity=true (used by getConversation) the decrypted
 * plaintext is re-hashed and compared to contentHash.  If they differ
 * obj.tampered is set to true so the client can warn the user.
 */
const decryptMessage = (msg, { checkIntegrity = false } = {}) => {
  const obj = msg.toObject ? msg.toObject() : { ...msg };

  let plaintext = "";
  let decryptOk = false;

  try {
    plaintext = decrypt({
      ciphertext: obj.content,
      iv:         obj.encryptionMeta?.iv,
      authTag:    obj.encryptionMeta?.authTag,
      keyVersion: obj.encryptionMeta?.keyVersion,
    });
    obj.content = plaintext;
    decryptOk   = true;
  } catch {
    obj.content = "";
  }

  // Layer 2 — passive integrity check on every read
  let tampered = false;
  if (checkIntegrity && decryptOk && obj.contentHash && obj.sentAt) {
    try {
      const recomputed = computeMessageHash(
        plaintext,
        String(obj.sender?._id || obj.sender),
        new Date(obj.sentAt).toISOString()
      );
      if (recomputed !== obj.contentHash) tampered = true;
    } catch { /* hash failure → treat as unknown, leave tampered=false */ }
  }

  // Build safe imageForensics for client
  // FIX: previous code read imageForensics.originalHash which never existed
  // (field stored by sendImage is serverHash).  Now correctly mapped.
  let safeForensics = null;
  if (obj.imageForensics?.serverHash) {
    safeForensics = {
      originalHash:         obj.imageForensics.serverHash,
      uploadIntegrityMatch: obj.imageForensics.uploadIntegrityMatch ?? null,
      uploadedAt:           obj.imageForensics.uploadedAt ?? null,
    };
  }

  // Strip all server-only fields
  delete obj.encryptionMeta;
  delete obj.contentHash;
  delete obj.senderSignature;
  delete obj.metadata;
  delete obj.accessLog;
  delete obj.editHistory;
  delete obj.imageEditHistory;
  delete obj.imageForensics;

  if (safeForensics) obj.imageForensics = safeForensics;

  // Expose counts for UI badges
  obj.imageEditCount = msg.imageEditHistory?.length || 0;
  obj.editCount      = msg.editHistory?.length || 0;

  // Layer 2 result visible to client
  obj.tampered = tampered;

  return obj;
};


// ═══════════════════════════════════════════════════════════════════
//  SEND TEXT MESSAGE
// ═══════════════════════════════════════════════════════════════════
exports.sendMessage = async (req, res) => {
  try {
    const { receiverUsername, content } = req.body;
    if (!content?.trim())
      return res.status(400).json({ success: false, message: "Message content required" });

    const receiver = await User.findOne({ username: receiverUsername?.toLowerCase(), isActive: true });
    if (!receiver)
      return res.status(404).json({ success: false, message: "Recipient not found" });

    const sender = await User.findById(req.user._id).select("friends blockedUsers");
    if (!sender.friends.map(String).includes(String(receiver._id)))
      return res.status(403).json({ success: false, message: "You can only message friends" });
    if (receiver.blockedUsers?.map(String).includes(String(req.user._id)))
      return res.status(403).json({ success: false, message: "Cannot send message to this user" });

    const plaintext       = content.trim();
    const sentAt          = new Date();
    const contentHash     = computeMessageHash(plaintext, req.user._id.toString(), sentAt.toISOString());
    const encrypted       = encrypt(plaintext);
    const senderSignature = generateMessageSignature(req.user._id.toString(), "pending", sentAt.toISOString());
    const metadata        = getMetadata(req.clientMeta);

    const message = await Message.create({
      sender: req.user._id, receiver: receiver._id,
      content: encrypted.ciphertext,
      encryptionMeta: { iv: encrypted.iv, authTag: encrypted.authTag, keyVersion: encrypted.keyVersion, algorithm: "AES-256-GCM" },
      messageType: "text", sentAt, contentHash, senderSignature, metadata,
    });

    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_SENT", targetType: "Message", targetId: message._id, details: { receiverUsername, length: plaintext.length } });

    const populated = await Message.findById(message._id)
      .populate("sender",   "username displayName profilePicture")
      .populate("receiver", "username displayName profilePicture");

    res.status(201).json({ success: true, data: decryptMessage(populated) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  SEND IMAGE MESSAGE
// ═══════════════════════════════════════════════════════════════════
exports.sendImage = async (req, res) => {
  try {
    const { receiverUsername, clientImageHash } = req.body;
    if (!req.file)     return res.status(400).json({ success: false, message: "No image provided" });
    if (!receiverUsername) return res.status(400).json({ success: false, message: "Receiver required" });

    const receiver = await User.findOne({ username: receiverUsername?.toLowerCase(), isActive: true });
    if (!receiver)
      return res.status(404).json({ success: false, message: "Recipient not found" });

    const sender = await User.findById(req.user._id).select("friends blockedUsers");
    if (!sender.friends.map(String).includes(String(receiver._id)))
      return res.status(403).json({ success: false, message: "You can only message friends" });

    // Layer 1: Transit integrity
    const serverHash = hashBuffer(req.file.buffer);
    const hashMatch  = clientImageHash ? clientImageHash === serverHash : null;

    const result    = await uploadToCloudinary(req.file.buffer, "bytechat/messages");
    const sentAt    = new Date();
    const plaintext = result.secure_url;
    const encrypted = encrypt(plaintext);
    const metadata  = getMetadata(req.clientMeta);

    const message = await Message.create({
      sender: req.user._id, receiver: receiver._id,
      content: encrypted.ciphertext,
      encryptionMeta: { iv: encrypted.iv, authTag: encrypted.authTag, keyVersion: encrypted.keyVersion, algorithm: "AES-256-GCM" },
      messageType: "image",
      attachment: { url: result.secure_url, publicId: result.public_id, width: result.width, height: result.height, format: result.format },
      sentAt,
      contentHash: computeMessageHash(plaintext, req.user._id.toString(), sentAt.toISOString()),
      senderSignature: generateMessageSignature(req.user._id.toString(), "pending", sentAt.toISOString()),
      metadata,
      imageForensics: {
        clientHash: clientImageHash || null,
        serverHash,                         // ground-truth hash
        uploadIntegrityMatch: hashMatch,
        uploadedAt:    sentAt,
        uploaderIp:    req.clientMeta?.ip,
        uploaderDevice: req.clientMeta?.device,
      },
    });

    if (hashMatch === false) {
      await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "TAMPER_DETECTED", targetType: "Message", targetId: message._id,
        details: { layer: "transit", reason: "clientHash !== serverHash on image upload — altered between browser and server", clientHash: clientImageHash, serverHash } });
    }

    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_SENT", targetType: "Message", targetId: message._id,
      details: { receiverUsername, messageType: "image", serverHash, uploadIntegrityMatch: hashMatch } });

    const populated = await Message.findById(message._id)
      .populate("sender",   "username displayName profilePicture")
      .populate("receiver", "username displayName profilePicture");

    res.status(201).json({ success: true, data: decryptMessage(populated) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  REPLACE IMAGE  (sender only — keeps full forensic history)
// ═══════════════════════════════════════════════════════════════════
exports.editImage = async (req, res) => {
  try {
    const { messageId } = req.params;
    const { clientImageHash } = req.body;
    if (!req.file) return res.status(400).json({ success: false, message: "No image provided" });

    const message = await Message.findById(messageId);
    if (!message)               return res.status(404).json({ success: false, message: "Message not found" });
    if (message.isDeleted)      return res.status(400).json({ success: false, message: "Cannot edit a deleted message" });
    if (!message.sender.equals(req.user._id)) return res.status(403).json({ success: false, message: "Cannot edit others' messages" });
    if (message.messageType !== "image")      return res.status(400).json({ success: false, message: "This message is not an image" });

    const previousAttachment = message.attachment.toObject();
    const previousServerHash = message.imageForensics?.serverHash || null;
    const previousClientHash = message.imageForensics?.clientHash || null;

    const newServerHash = hashBuffer(req.file.buffer);
    const newHashMatch  = clientImageHash ? clientImageHash === newServerHash : null;

    if (newHashMatch === false) {
      await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "TAMPER_DETECTED", targetType: "Message", targetId: message._id,
        details: { layer: "transit", reason: "clientHash !== serverHash during image replacement", clientHash: clientImageHash, serverHash: newServerHash } });
    }

    const result = await uploadToCloudinary(req.file.buffer, "bytechat/messages");
    // NOTE: old Cloudinary asset intentionally NOT deleted — retained for forensic retrieval.

    message.imageEditHistory.push({
      previousAttachment, previousServerHash, previousClientHash,
      newServerHash, newClientHash: clientImageHash || null,
      newUploadIntegrityMatch: newHashMatch,
      editedAt: new Date(), editedByIp: req.clientMeta?.ip, editedDevice: req.clientMeta?.device,
    });

    message.attachment    = { url: result.secure_url, publicId: result.public_id, width: result.width, height: result.height, format: result.format };
    message.imageForensics = { clientHash: clientImageHash || null, serverHash: newServerHash, uploadIntegrityMatch: newHashMatch, uploadedAt: new Date(), uploaderIp: req.clientMeta?.ip, uploaderDevice: req.clientMeta?.device };

    const newPlaintext    = result.secure_url;
    const newEncrypted    = encrypt(newPlaintext);
    message.content       = newEncrypted.ciphertext;
    message.encryptionMeta = { iv: newEncrypted.iv, authTag: newEncrypted.authTag, keyVersion: newEncrypted.keyVersion, algorithm: "AES-256-GCM" };
    message.contentHash   = computeMessageHash(newPlaintext, req.user._id.toString(), message.sentAt.toISOString());

    await message.save();
    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_EDITED", targetType: "Message", targetId: message._id,
      details: { type: "image_replacement", editNumber: message.imageEditHistory.length, previousServerHash, newServerHash, newUploadIntegrityMatch: newHashMatch } });

    const populated = await Message.findById(message._id)
      .populate("sender",   "username displayName profilePicture")
      .populate("receiver", "username displayName profilePicture");

    res.json({ success: true, message: "Image replaced", data: decryptMessage(populated) });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  LAYER 3 — VERIFY IMAGE AUTHENTICITY  (POST /:id/verify-image)
// ═══════════════════════════════════════════════════════════════════
exports.verifyImageHash = async (req, res) => {
  try {
    const { messageId } = req.params;
    if (!req.file) return res.status(400).json({ success: false, message: "No image file provided for comparison" });

    const message = await Message.findById(messageId);
    if (!message)                          return res.status(404).json({ success: false, message: "Message not found" });
    if (message.messageType !== "image")   return res.status(400).json({ success: false, message: "This message is not an image" });
    if (!message.sender.equals(req.user._id) && !message.receiver.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Access denied" });

    const storedHash = message.imageForensics?.serverHash;
    if (!storedHash)
      return res.status(400).json({ success: false, message: "No original hash on record — image may predate tamper detection" });

    const comparisonHash = hashBuffer(req.file.buffer);
    const isAuthentic    = comparisonHash === storedHash;
    const verifiedByRole = message.sender.equals(req.user._id) ? "sender" : "receiver";

    // FIX: was incorrectly logging "MESSAGE_READ" for the authentic case.
    // Correct action is IMAGE_VERIFIED for both outcomes, plus a separate
    // TAMPER_DETECTED log when the image doesn't match.
    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "IMAGE_VERIFIED", targetType: "Message", targetId: message._id,
      details: { result: isAuthentic ? "AUTHENTIC" : "TAMPERED_OR_EDITED", storedHash, comparisonHash, verifiedByRole } });

    if (!isAuthentic) {
      await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "TAMPER_DETECTED", targetType: "Message", targetId: message._id,
        details: { layer: "post_send", reason: "Image copy SHA-256 does not match original — edited after sending", storedHash, comparisonHash, verifiedByRole } });
    }

    res.json({
      success: true,
      data: {
        messageId, authentic: isAuthentic,
        storedHash, comparisonHash, hashMatch: isAuthentic,
        uploadIntegrityMatch: message.imageForensics?.uploadIntegrityMatch ?? null,
        uploadedAt:           message.imageForensics?.uploadedAt ?? null,
        hasBeenReplaced:      (message.imageEditHistory?.length || 0) > 0,
        replacementCount:     message.imageEditHistory?.length || 0,
        result: isAuthentic
          ? "AUTHENTIC — Image matches the original sent by the sender"
          : "ALTERED — This image does not match what was originally sent",
        detail: isAuthentic
          ? "SHA-256 hashes match. The image bytes are identical to the original upload. No editing, cropping, filtering or re-saving has occurred."
          : "SHA-256 hashes do not match. The image has been altered — cropped, annotated, filtered, re-saved, or screenshotted after the original was sent.",
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  LAYER 4 — VERIFY TEXT INTEGRITY  (GET /:id/verify-text)
//  On-demand explicit proof that a text message was never tampered
//  with at the database level.
// ═══════════════════════════════════════════════════════════════════
exports.verifyTextIntegrity = async (req, res) => {
  try {
    const { messageId } = req.params;

    const message = await Message.findById(messageId);
    if (!message) return res.status(404).json({ success: false, message: "Message not found" });
    if (message.messageType !== "text") return res.status(400).json({ success: false, message: "This endpoint is for text messages only" });
    if (!message.sender.equals(req.user._id) && !message.receiver.equals(req.user._id))
      return res.status(403).json({ success: false, message: "Access denied" });
    if (!message.contentHash)
      return res.status(400).json({ success: false, message: "No content hash on record — message may predate tamper detection" });

    let plaintext = "", decryptOk = false;
    try {
      plaintext  = decrypt({ ciphertext: message.content, iv: message.encryptionMeta?.iv, authTag: message.encryptionMeta?.authTag, keyVersion: message.encryptionMeta?.keyVersion });
      decryptOk  = true;
    } catch { /* decryption failure itself is a tamper signal */ }

    let isIntact = false, recomputedHash = null;
    if (decryptOk) {
      recomputedHash = computeMessageHash(plaintext, String(message.sender), new Date(message.sentAt).toISOString());
      isIntact       = recomputedHash === message.contentHash;
    }

    const verifiedByRole = message.sender.equals(req.user._id) ? "sender" : "receiver";

    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: isIntact ? "TEXT_VERIFIED" : "TAMPER_DETECTED", targetType: "Message", targetId: message._id,
      details: { layer: "storage", result: isIntact ? "INTACT" : (decryptOk ? "HASH_MISMATCH" : "DECRYPTION_FAILED"), storedHash: message.contentHash, recomputedHash, verifiedByRole } });

    if (!isIntact) {
      await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "TAMPER_DETECTED", targetType: "Message", targetId: message._id,
        details: { layer: "storage", reason: decryptOk ? "contentHash mismatch — DB content modified outside application" : "AES-GCM decryption failed — ciphertext/IV/authTag corrupted", storedHash: message.contentHash, recomputedHash } });
    }

    res.json({
      success: true,
      data: {
        messageId, intact: isIntact, decryptionOk: decryptOk,
        storedHash: message.contentHash, recomputedHash,
        editCount:     message.editHistory?.length || 0,
        hasBeenEdited: (message.editHistory?.length || 0) > 0,
        result: isIntact
          ? "INTACT — Message content has not been tampered with"
          : decryptOk
            ? "TAMPERED — Hash mismatch: stored content was modified directly in the database"
            : "TAMPERED — Decryption failed: ciphertext, IV or authentication tag was corrupted",
        detail: isIntact
          ? "HMAC-SHA256 of the decrypted content matches the hash computed at send time. The message is authentic."
          : "The message content does not match its original hash. The database record has been modified outside the application.",
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  GET CONVERSATION
//  Runs Layer 2 passive integrity check on every message.
//  Messages that fail have tampered:true so the UI can warn the user.
// ═══════════════════════════════════════════════════════════════════
exports.getConversation = async (req, res) => {
  try {
    const { username }             = req.params;
    const { page = 1, limit = 50 } = req.query;

    const otherUser = await User.findOne({ username: username?.toLowerCase() });
    if (!otherUser) return res.status(404).json({ success: false, message: "User not found" });

    const messages = await Message.find({
      $or: [{ sender: req.user._id, receiver: otherUser._id }, { sender: otherUser._id, receiver: req.user._id }],
      isDeleted: false,
    })
      .sort({ sentAt: -1 })
      .skip((page - 1) * Number(limit))
      .limit(Number(limit))
      .populate("sender",   "username displayName profilePicture")
      .populate("receiver", "username displayName profilePicture");

    const unreadIds = messages
      .filter(m => String(m.receiver?._id || m.receiver) === String(req.user._id) && !m.readAt)
      .map(m => m._id);

    if (unreadIds.length) {
      await Message.updateMany(
        { _id: { $in: unreadIds } },
        { $set: { readAt: new Date() }, $push: { accessLog: { accessedBy: req.user._id, action: "read", accessIp: req.clientMeta?.ip } } }
      );
    }

    // Decrypt all messages with Layer 2 integrity check
    const decrypted = messages.reverse().map(m => decryptMessage(m, { checkIntegrity: true }));

    // Log any tamper detections found during bulk read (fire-and-forget)
    decrypted
      .filter(m => m.tampered)
      .forEach(m => {
        logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "TAMPER_DETECTED", targetType: "Message", targetId: m._id,
          details: { layer: "storage", reason: "contentHash mismatch detected during getConversation" } }).catch(() => {});
      });

    res.json({ success: true, data: decrypted });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  DELETE MESSAGE  (soft delete)
// ═══════════════════════════════════════════════════════════════════
exports.deleteMessage = async (req, res) => {
  try {
    const message = await Message.findById(req.params.messageId);
    if (!message)                         return res.status(404).json({ success: false, message: "Message not found" });
    if (!message.sender.equals(req.user._id)) return res.status(403).json({ success: false, message: "Cannot delete others' messages" });

    message.isDeleted = true;
    message.deletedAt = new Date();
    await message.save();

    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_DELETED", targetType: "Message", targetId: message._id });
    res.json({ success: true, message: "Message deleted" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  EDIT TEXT MESSAGE
//  Pushes old encrypted content + hash to editHistory before overwriting.
// ═══════════════════════════════════════════════════════════════════
exports.editMessage = async (req, res) => {
  try {
    const { content } = req.body;
    if (!content?.trim()) return res.status(400).json({ success: false, message: "Content required" });

    const message = await Message.findById(req.params.messageId);
    if (!message)             return res.status(404).json({ success: false, message: "Message not found" });
    // FIX: was missing isDeleted guard — deleted messages could previously be edited
    if (message.isDeleted)    return res.status(400).json({ success: false, message: "Cannot edit a deleted message" });
    if (!message.sender.equals(req.user._id)) return res.status(403).json({ success: false, message: "Cannot edit others' messages" });
    if (message.messageType === "image")      return res.status(400).json({ success: false, message: "Use PATCH /:id/image to replace an image" });

    const newPlaintext = content.trim();

    message.editHistory.push({
      previousContent: { ciphertext: message.content, iv: message.encryptionMeta.iv, authTag: message.encryptionMeta.authTag, keyVersion: message.encryptionMeta.keyVersion },
      previousHash:    message.contentHash,
      editedByIp:      req.clientMeta?.ip,
    });

    message.contentHash    = computeMessageHash(newPlaintext, req.user._id.toString(), message.sentAt.toISOString());
    const newEncrypted     = encrypt(newPlaintext);
    message.content        = newEncrypted.ciphertext;
    message.encryptionMeta = { iv: newEncrypted.iv, authTag: newEncrypted.authTag, keyVersion: newEncrypted.keyVersion, algorithm: "AES-256-GCM" };

    await message.save();
    await logAction({ req, actor: { userId: req.user._id, username: req.user.username }, action: "MESSAGE_EDITED", targetType: "Message", targetId: message._id, details: { editNumber: message.editHistory.length } });

    res.json({ success: true, message: "Message updated", data: { content: newPlaintext } });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};


// ═══════════════════════════════════════════════════════════════════
//  AI IMAGE EDIT PROXY  (POST /messages/ai-edit-proxy)
//
//  Browsers cannot call api.anthropic.com directly — CORS blocks it.
//  This endpoint sits on your own server, calls Claude with the image
//  URL + instruction, and returns the edit specification to the client.
//  The actual pixel editing still happens on the client canvas.
// ═══════════════════════════════════════════════════════════════════
exports.aiImageEditProxy = async (req, res) => {
  try {
    const { imageUrl, editType, prompt } = req.body;
    if (!imageUrl || !editType || !prompt)
      return res.status(400).json({ success: false, message: "imageUrl, editType and prompt are required" });

    const fetch = (...args) => import("node-fetch").then(({ default: f }) => f(...args));

    // Fetch the image and convert to base64 so Claude can read it
    const imgRes  = await fetch(imageUrl);
    const imgBuf  = await imgRes.buffer();
    const mimeType = imgRes.headers.get("content-type") || "image/jpeg";
    const base64  = imgBuf.toString("base64");

    // Call Claude Vision
    const aiRes = await fetch("https://api.anthropic.com/v1/messages", {
      method:  "POST",
      headers: {
        "Content-Type":      "application/json",
        "x-api-key":         process.env.ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model:      "claude-sonnet-4-20250514",
        max_tokens: 1000,
        messages: [{
          role: "user",
          content: [
            { type: "image", source: { type: "base64", media_type: mimeType, data: base64 } },
            { type: "text",  text: `You are an image editing assistant. The user wants to edit this image.
Edit type: ${editType}
Instruction: ${prompt}

Respond ONLY with a valid JSON object — no markdown, no explanation:
{
  "editSummary": "one sentence describing what was edited",
  "cssFilter": "CSS filter string e.g. 'brightness(1.2) saturate(1.5)' or 'grayscale(1)' or '' if not applicable",
  "canvasOp": "none|rotate90|rotate180|rotate270|flipH|flipV|crop_square",
  "overlayText": "text to draw on image or empty string",
  "overlayTextColor": "#ffffff",
  "overlayTextPosition": "bottom-center|top-center|center",
  "brightness": 1.0,
  "contrast": 1.0,
  "saturation": 1.0
}` },
          ],
        }],
      }),
    });

    const aiData  = await aiRes.json();
    const rawText = aiData.content?.find(c => c.type === "text")?.text || "{}";

    let editSpec;
    try {
      const clean  = rawText.replace(/```json|```/g, "").trim();
      editSpec = JSON.parse(clean);
    } catch {
      editSpec = { editSummary: prompt, cssFilter: "", canvasOp: "none", overlayText: "" };
    }

    res.json({ success: true, data: editSpec });
  } catch (err) {
    console.error("[aiImageEditProxy]", err.message);
    res.status(500).json({ success: false, message: "AI edit failed: " + err.message });
  }
};