// ── rateLimit.middleware.js ───────────────────────────────────────
// Drop-in replacement — loosened limits so polling doesn't trigger 429.
// Import this wherever you currently use express-rate-limit.

const rateLimit = require('express-rate-limit');

// ── General API limit ─────────────────────────────────────────────
// 300 requests per minute per IP — enough for normal chat usage
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests — please slow down' },
  skip: req => req.method === 'OPTIONS',
});

// ── Conversation polling limit ────────────────────────────────────
// This endpoint is hit every 10s per open chat.
// 60 req/min = polling every second — way more than we need.
// Set generously so normal use never hits it.
const conversationLimiter = rateLimit({
  windowMs: 60 * 1000,       // 1 minute
  max: 120,                  // 2 req/sec max — fine for 10s polling
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests — please slow down' },
  keyGenerator: req => `conv_${req.ip}_${req.params?.username || ''}`,
});

// ── Auth limit (strict — prevent brute force) ─────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,  // 15 minutes
  max: 20,                   // 20 login attempts per 15 min
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many login attempts — try again in 15 minutes' },
});

// ── Image upload limit ────────────────────────────────────────────
const uploadLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,                   // 30 uploads/min is plenty
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many uploads — please wait' },
});

module.exports = { generalLimiter, conversationLimiter, authLimiter, uploadLimiter };
