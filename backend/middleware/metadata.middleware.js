const DeviceDetector = require("device-detector-js");
const detector = new DeviceDetector();

/**
 * Silently captures IP + device metadata on every request.
 * Attached to req.clientMeta — never shown to the user.
 * Used internally for forensic logging only.
 */
const captureMetadata = (req, res, next) => {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.headers["x-real-ip"] ||
    req.connection?.remoteAddress ||
    req.socket?.remoteAddress ||
    req.ip ||
    "unknown";

  const ua = req.headers["user-agent"] || "";
  let deviceInfo = { device: "unknown", deviceBrand: "", os: "unknown", client: "unknown" };

  try {
    const parsed = detector.parse(ua);
    deviceInfo = {
      device: parsed.device?.type || "unknown",
      deviceBrand: parsed.device?.brand || "",
      os: parsed.os?.name ? `${parsed.os.name} ${parsed.os.version || ""}`.trim() : "unknown",
      client: parsed.client?.name
        ? `${parsed.client.name} ${parsed.client.version || ""}`.trim()
        : "unknown",
    };
  } catch (_) {}

  // Always capture — no consent check, for forensic purposes
  req.clientMeta = {
    ip,
    device: deviceInfo.device,
    deviceBrand: deviceInfo.deviceBrand,
    os: deviceInfo.os,
    client: deviceInfo.client,
    userAgent: ua,
    capturedAt: new Date(),
  };

  next();
};

/**
 * Returns full metadata object — always populated, no consent gate.
 * Used when saving messages to DB.
 */
const getMetadata = (clientMeta) => ({
  senderIp: clientMeta?.ip || "unknown",
  senderDevice: `${clientMeta?.device || ""} ${clientMeta?.deviceBrand || ""}`.trim() || "unknown",
  senderOs: clientMeta?.os || "unknown",
  senderClient: clientMeta?.client || "unknown",
  senderUserAgent: clientMeta?.userAgent || "",
});

module.exports = { captureMetadata, getMetadata };