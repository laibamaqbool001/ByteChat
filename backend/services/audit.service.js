const AuditLog = require("../models/AuditLog.model");
const { computeAuditEntryHash } = require("../utils/hash.utils");

/**
 * Central audit logger — call this for every sensitive action.
 * Creates an immutable, hashed log entry for chain of custody.
 *
 * @param {Object} params
 * @param {Object} params.req          - Express request (for IP/device)
 * @param {Object} params.actor        - { userId, username }
 * @param {string} params.action       - One of AuditLog.action enum values
 * @param {string} params.targetType   - "User" | "Message" | etc.
 * @param {*}      params.targetId     - ObjectId of the target
 * @param {Object} params.details      - Any extra structured data
 */
const logAction = async ({ req, actor, action, targetType, targetId, details = {} }) => {
  try {
    const ip =
      req?.headers?.["x-forwarded-for"]?.split(",")[0]?.trim() ||
      req?.connection?.remoteAddress ||
      req?.ip ||
      "system";

    const device = req?.clientMeta?.device || "unknown";
    const timestamp = new Date();

    const entry = {
      actor: {
        userId: actor?.userId || null,
        username: actor?.username || "system",
        ip,
        device,
      },
      action,
      targetType,
      targetId,
      details,
      timestamp,
    };

    // Compute integrity hash of this log entry
    entry.entryHash = computeAuditEntryHash(entry);

    await AuditLog.create(entry);
  } catch (err) {
    // Log errors should never crash the main flow
    console.error("[AuditLogger] Failed to write audit log:", err.message);
  }
};

/**
 * Retrieve audit logs for a specific target (chain of custody view)
 */
const getChainOfCustody = async (targetId, targetType) => {
  return AuditLog.find({ targetId, targetType })
    .sort({ timestamp: 1 })
    .populate("actor.userId", "username email");
};

/**
 * Retrieve all actions performed by a specific user
 */
const getUserActivityLog = async (userId, { page = 1, limit = 50 } = {}) => {
  return AuditLog.find({ "actor.userId": userId })
    .sort({ timestamp: -1 })
    .skip((page - 1) * limit)
    .limit(limit);
};

module.exports = { logAction, getChainOfCustody, getUserActivityLog };
