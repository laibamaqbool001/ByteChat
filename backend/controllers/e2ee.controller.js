/**
 * E2EE Key Management Controller
 * ──────────────────────────────────────────────────────────────────
 * Handles the server-side key store for the X3DH-inspired key exchange.
 *
 * The server stores ONLY public keys.
 * Private keys are generated on the client and NEVER sent here.
 *
 * Endpoints:
 *   POST /api/e2ee/keys           — Register/update public key bundle
 *   GET  /api/e2ee/keys/:username — Fetch a user's public key bundle (to encrypt for them)
 *   POST /api/e2ee/keys/prekeys   — Replenish one-time prekeys
 *   GET  /api/e2ee/keys/me        — Get own key registration status
 *   POST /api/e2ee/verify         — Verify a prekey signature
 */

const User = require("../models/User.model");
const { verifySignature } = require("../utils/crypto.utils");
const { logAction } = require("../services/audit.service");

// ── Register public key bundle ─────────────────────────────────────
exports.registerKeys = async (req, res) => {
  try {
    const {
      publicKey,          // base64 SPKI DER — ECDH identity key
      signedPreKey,       // { keyId, publicKey, signature }
      oneTimePreKeys,     // [{ keyId, publicKey }, ...]  (max 100)
    } = req.body;

    if (!publicKey) {
      return res.status(400).json({ success: false, message: "publicKey is required" });
    }

    // Validate signed prekey signature if provided
    if (signedPreKey) {
      const { keyId, publicKey: spkPublic, signature } = signedPreKey;
      if (!keyId || !spkPublic || !signature) {
        return res.status(400).json({ success: false, message: "signedPreKey must have keyId, publicKey, signature" });
      }

      // The signature covers the prekey's public key bytes
      const valid = verifySignature(
        Buffer.from(spkPublic, "base64"),
        signature,
        publicKey  // signed with identity key
      );
      if (!valid) {
        return res.status(400).json({ success: false, message: "signedPreKey signature verification failed" });
      }
    }

    // Validate one-time prekeys
    if (oneTimePreKeys && (!Array.isArray(oneTimePreKeys) || oneTimePreKeys.length > 100)) {
      return res.status(400).json({ success: false, message: "oneTimePreKeys must be an array of max 100 keys" });
    }

    const user = await User.findById(req.user._id);

    user.e2ee = {
      publicKey,
      signedPreKey: signedPreKey || user.e2ee?.signedPreKey,
      oneTimePreKeys: oneTimePreKeys || user.e2ee?.oneTimePreKeys || [],
      registeredAt: new Date(),
      keyVersion: (user.e2ee?.keyVersion || 0) + 1,
    };

    await user.save();

    await logAction({
      req,
      actor: { userId: user._id, username: user.username },
      action: "PROFILE_UPDATED",
      targetType: "User",
      targetId: user._id,
      details: {
        e2ee: "keys_registered",
        keyVersion: user.e2ee.keyVersion,
        oneTimePreKeyCount: user.e2ee.oneTimePreKeys.length,
      },
    });

    res.json({
      success: true,
      message: "E2EE public keys registered",
      data: {
        keyVersion: user.e2ee.keyVersion,
        oneTimePreKeysStored: user.e2ee.oneTimePreKeys.length,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Fetch key bundle for a user (to encrypt a message for them) ────
exports.getKeyBundle = async (req, res) => {
  try {
    const { username } = req.params;

    const target = await User.findOne({ username: username.toLowerCase(), isActive: true })
      .select("username e2ee");

    if (!target) return res.status(404).json({ success: false, message: "User not found" });

    if (!target.e2ee?.publicKey) {
      return res.status(404).json({
        success: false,
        message: `${username} has not registered E2EE keys — they may be on an older client`,
      });
    }

    // Pop one one-time prekey (consumed per session)
    let oneTimePreKey = null;
    if (target.e2ee.oneTimePreKeys && target.e2ee.oneTimePreKeys.length > 0) {
      oneTimePreKey = target.e2ee.oneTimePreKeys.shift(); // consume from front
      await User.findByIdAndUpdate(target._id, {
        $pop: { "e2ee.oneTimePreKeys": -1 },
      });
    }
    // If pool is empty, warn — receiver should upload more
    const remainingPreKeys = target.e2ee.oneTimePreKeys.length - (oneTimePreKey ? 1 : 0);

    res.json({
      success: true,
      data: {
        username: target.username,
        identityKey: target.e2ee.publicKey,
        signedPreKey: target.e2ee.signedPreKey,
        oneTimePreKey,                    // null if pool exhausted
        keyVersion: target.e2ee.keyVersion,
        warning: oneTimePreKey === null
          ? "One-time prekey pool exhausted — forward secrecy degraded for this session"
          : remainingPreKeys < 5
          ? "Low on one-time prekeys — receiver should replenish"
          : undefined,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Replenish one-time prekeys ─────────────────────────────────────
exports.uploadPreKeys = async (req, res) => {
  try {
    const { oneTimePreKeys } = req.body;

    if (!Array.isArray(oneTimePreKeys) || oneTimePreKeys.length === 0) {
      return res.status(400).json({ success: false, message: "oneTimePreKeys array required" });
    }
    if (oneTimePreKeys.length > 100) {
      return res.status(400).json({ success: false, message: "Max 100 prekeys per upload" });
    }

    const user = await User.findById(req.user._id);

    if (!user.e2ee?.publicKey) {
      return res.status(400).json({ success: false, message: "Register your identity key first" });
    }

    const currentCount = user.e2ee.oneTimePreKeys?.length || 0;
    if (currentCount + oneTimePreKeys.length > 200) {
      return res.status(400).json({ success: false, message: "Prekey pool would exceed max of 200" });
    }

    await User.findByIdAndUpdate(req.user._id, {
      $push: { "e2ee.oneTimePreKeys": { $each: oneTimePreKeys } },
    });

    res.json({
      success: true,
      message: `${oneTimePreKeys.length} one-time prekeys uploaded`,
      data: { totalPreKeys: currentCount + oneTimePreKeys.length },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Get own E2EE key status ────────────────────────────────────────
exports.getMyKeyStatus = async (req, res) => {
  try {
    const user = await User.findById(req.user._id).select("e2ee");

    if (!user.e2ee?.publicKey) {
      return res.json({
        success: true,
        data: { registered: false, message: "No E2EE keys registered" },
      });
    }

    res.json({
      success: true,
      data: {
        registered: true,
        keyVersion: user.e2ee.keyVersion,
        registeredAt: user.e2ee.registeredAt,
        hasSignedPreKey: !!user.e2ee.signedPreKey,
        oneTimePreKeysRemaining: user.e2ee.oneTimePreKeys?.length || 0,
        needsPreKeyReplenishment: (user.e2ee.oneTimePreKeys?.length || 0) < 5,
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ── Verify a prekey signature (utility for clients) ────────────────
exports.verifyPreKeySignature = async (req, res) => {
  try {
    const { username, preKeyPublic, signature } = req.body;

    const target = await User.findOne({ username: username.toLowerCase() }).select("e2ee");
    if (!target?.e2ee?.publicKey) {
      return res.status(404).json({ success: false, message: "User or keys not found" });
    }

    const valid = verifySignature(
      Buffer.from(preKeyPublic, "base64"),
      signature,
      target.e2ee.publicKey
    );

    res.json({
      success: true,
      data: {
        valid,
        message: valid
          ? "Prekey signature is valid — key belongs to this user"
          : "⚠ Prekey signature INVALID — possible key substitution attack",
      },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
