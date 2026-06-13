// ── email.service.js ─────────────────────────────────────────────
// Uses Nodemailer. Install: npm install nodemailer
// Add to .env:
//   EMAIL_HOST=smtp.gmail.com
//   EMAIL_PORT=587
//   EMAIL_USER=your@gmail.com
//   EMAIL_PASS=your_app_password   ← Gmail App Password (not your real password)
//   EMAIL_FROM=ByteChat <your@gmail.com>
//   CLIENT_URL=http://localhost:3000

const nodemailer = require('nodemailer');
const crypto     = require('crypto');

const transporter = nodemailer.createTransport({
  host:   process.env.EMAIL_HOST   || 'smtp.gmail.com',
  port:   Number(process.env.EMAIL_PORT || 587),
  secure: false,                     // true for port 465, false for 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Generate a secure random token
const generateToken = () => crypto.randomBytes(32).toString('hex');

// ── Send activation email ─────────────────────────────────────────
const sendActivationEmail = async (toEmail, displayName, activationToken) => {
  const base = process.env.CLIENT_URL || 'http://localhost:3000';
  // For plain HTML frontend — token is read by handleActivationLink() on page load
const activationUrl = `${process.env.CLIENT_URL || 'http://localhost:3000'}/index.html?token=${activationToken}`;

  const html = `
  <!DOCTYPE html>
  <html>
  <head><meta charset="UTF-8"/></head>
  <body style="margin:0;padding:0;background:#F0F6FF;font-family:'Segoe UI',Arial,sans-serif">
    <div style="max-width:520px;margin:40px auto;background:#fff;border-radius:20px;overflow:hidden;box-shadow:0 8px 32px rgba(74,144,217,.15)">
      <!-- Header -->
      <div style="background:linear-gradient(135deg,#5B9FE3,#2063A8);padding:36px 32px;text-align:center">
        <div style="width:64px;height:64px;background:rgba(255,255,255,.2);border-radius:16px;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px">
          <svg width="36" height="36" viewBox="0 0 44 44" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect x="5" y="7" width="34" height="24" rx="7" fill="white" fill-opacity=".92"/>
            <circle cx="15" cy="19" r="2.5" fill="#2B6CB0"/>
            <circle cx="22" cy="19" r="2.5" fill="#2B6CB0"/>
            <circle cx="29" cy="19" r="2.5" fill="#2B6CB0"/>
            <path d="M14 31 L9 38 L22 34" fill="white" fill-opacity=".85"/>
          </svg>
        </div>
        <h1 style="color:#fff;margin:0;font-size:24px;font-weight:700;letter-spacing:-.5px">ByteChat</h1>
        <p style="color:rgba(255,255,255,.75);margin:6px 0 0;font-size:13px;letter-spacing:1px;text-transform:uppercase">Activate Your Account</p>
      </div>
      <!-- Body -->
      <div style="padding:36px 32px">
        <h2 style="margin:0 0 10px;font-size:20px;color:#1A2840">Welcome, ${displayName}! 👋</h2>
        <p style="color:#6B84A3;font-size:15px;line-height:1.65;margin:0 0 28px">
          You're one step away from joining ByteChat. Click the button below to activate your account and start messaging securely.
        </p>
        <!-- CTA Button -->
        <div style="text-align:center;margin-bottom:28px">
          <a href="${activationUrl}" style="display:inline-block;background:linear-gradient(135deg,#5B9FE3,#2063A8);color:#fff;text-decoration:none;padding:14px 36px;border-radius:12px;font-size:15px;font-weight:600;letter-spacing:.3px;box-shadow:0 4px 14px rgba(74,144,217,.4)">
            ✓ Activate My Account
          </a>
        </div>
        <!-- Token fallback -->
        <div style="background:#F0F6FF;border-radius:10px;padding:14px 16px;margin-bottom:24px">
          <p style="color:#6B84A3;font-size:12px;margin:0 0 6px;font-weight:600;text-transform:uppercase;letter-spacing:.5px">Or paste this link in your browser:</p>
          <p style="color:#2B6CB0;font-size:12px;margin:0;word-break:break-all;font-family:monospace">${activationUrl}</p>
        </div>
        <!-- Expiry notice -->
        <p style="color:#6B84A3;font-size:13px;margin:0;text-align:center">
          This link expires in <strong>24 hours</strong>. If you didn't sign up for ByteChat, you can ignore this email.
        </p>
      </div>
      <!-- Footer -->
      <div style="background:#F8FBFF;padding:20px 32px;text-align:center;border-top:1px solid #C8DCEF">
        <p style="color:#6B84A3;font-size:12px;margin:0">© ${new Date().getFullYear()} ByteChat · Secure · Encrypted · Private</p>
      </div>
    </div>
  </body>
  </html>`;

  await transporter.sendMail({
    from:    process.env.EMAIL_FROM || `ByteChat <${process.env.EMAIL_USER}>`,
    to:      toEmail,
    subject: '✉️ Activate your ByteChat account',
    html,
  });
};

// ── Send password reset email ─────────────────────────────────────
const sendPasswordResetEmail = async (toEmail, displayName, resetToken) => {
  const resetUrl = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password?token=${resetToken}`;
  await transporter.sendMail({
    from:    process.env.EMAIL_FROM || `ByteChat <${process.env.EMAIL_USER}>`,
    to:      toEmail,
    subject: '🔒 Reset your ByteChat password',
    html: `
    <div style="max-width:500px;margin:40px auto;font-family:Arial,sans-serif;background:#fff;border-radius:16px;padding:32px;box-shadow:0 4px 20px rgba(0,0,0,.1)">
      <h2 style="color:#1A2840">Password Reset Request</h2>
      <p style="color:#6B84A3">Hi ${displayName}, we received a request to reset your password.</p>
      <a href="${resetUrl}" style="display:inline-block;background:#2063A8;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600;margin:16px 0">Reset Password</a>
      <p style="color:#6B84A3;font-size:13px">This link expires in 1 hour. If you didn't request this, ignore this email.</p>
    </div>`,
  });
};

module.exports = { generateToken, sendActivationEmail, sendPasswordResetEmail };