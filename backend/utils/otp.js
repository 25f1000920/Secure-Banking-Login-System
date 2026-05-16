// backend/utils/otp.js
'use strict';

const crypto     = require('crypto');
const nodemailer = require('nodemailer');
const db         = require('../config/db');
require('dotenv').config();

const OTP_TTL = parseInt(process.env.OTP_TTL_MINUTES || '5');

// ─── Email Transporter ────────────────────────────────────────
const transporter = nodemailer.createTransport({
  host:   process.env.SMTP_HOST || 'smtp.gmail.com',
  port:   parseInt(process.env.SMTP_PORT) || 587,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// ─── Generate cryptographically secure 6-digit OTP ───────────
function generateOtp() {
  // Use 4 bytes (32 bits) so the modulo bias is negligible for 900000 range
  const buf = crypto.randomBytes(4);
  const num = (buf.readUInt32BE(0) >>> 0) % 900000 + 100000; // 100000–999999
  return String(num);
}

// ─── Save OTP to DB (invalidates previous OTPs for same purpose) ─
async function createOtp(userId, purpose) {
  const code = generateOtp();

  // Invalidate old OTPs for this user + purpose
  await db.query(
    'UPDATE otps SET used = true WHERE user_id = $1 AND purpose = $2 AND used = false',
    [userId, purpose]
  );

  await db.query(
    `INSERT INTO otps (user_id, otp_code, purpose, expires_at) 
     VALUES ($1, $2, $3, NOW() + interval '${OTP_TTL} minutes')`,
    [userId, code, purpose]
  );

  return code;
}

// ─── Verify OTP ───────────────────────────────────────────────
async function verifyOtp(userId, code, purpose) {
  const { rows } = await db.query(
    `SELECT id FROM otps
     WHERE user_id = $1 AND otp_code = $2 AND purpose = $3
       AND used = false AND expires_at > NOW()
     LIMIT 1`,
    [userId, code, purpose]
  );

  if (!rows.length) return false;

  // Mark as used (single-use OTP)
  await db.query('UPDATE otps SET used = true WHERE id = $1', [rows[0].id]);
  return true;
}

// ─── Email Templates ──────────────────────────────────────────
function otpEmail(otp, purpose) {
  const labels = {
    login_verify:    'Login Verification',
    register_verify: 'Account Registration',
    forgot_password: 'Password Reset',
  };
  const label = labels[purpose] || 'Verification';

  return {
    subject: `YaTanDeoSidSai Bank — Your ${label} OTP`,
    html: `
      <div style="font-family:'Segoe UI',sans-serif;max-width:480px;margin:auto;background:#0a0e1a;color:#e8d5b0;border-radius:12px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#c8a96e,#8b6914);padding:24px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;letter-spacing:2px;color:#fff;">YaTanDeoSidSai Banking</h1>
          <p style="margin:4px 0 0;font-size:12px;opacity:.8;letter-spacing:1px;">SECURE • TRUSTED • ELITE</p>
        </div>
        <div style="padding:32px;">
          <p style="font-size:16px;color:#c8a96e;margin:0 0 8px;">${label} OTP</p>
          <p style="color:#aaa;font-size:14px;margin:0 0 24px;">Use the code below to complete your ${label.toLowerCase()}:</p>
          <div style="background:#111827;border:1px solid #c8a96e44;border-radius:8px;padding:20px;text-align:center;margin-bottom:24px;">
            <span style="font-size:40px;font-weight:700;letter-spacing:12px;color:#c8a96e;">${otp}</span>
          </div>
          <p style="color:#888;font-size:13px;margin:0;">This OTP expires in <strong style="color:#e8d5b0;">${OTP_TTL} minutes</strong>. Do not share it with anyone.</p>
          <p style="color:#888;font-size:13px;margin:12px 0 0;">If you did not request this, please contact support immediately.</p>
        </div>
        <div style="background:#050810;padding:16px 32px;text-align:center;">
          <p style="color:#555;font-size:12px;margin:0;">© ${new Date().getFullYear()} YaTanDeoSidSai Banking. All rights reserved.</p>
        </div>
      </div>
    `,
  };
}

// ─── Send OTP Email ───────────────────────────────────────────
async function sendOtpEmail(toEmail, otp, purpose) {
  const { subject, html } = otpEmail(otp, purpose);
  await transporter.sendMail({
    from:    process.env.SMTP_FROM || 'YaTanDeoSidSai Bank <noreply@ytdss.bank>',
    to:      toEmail,
    subject,
    html,
  });
}

// ─── Send Account Lock Alert ──────────────────────────────────
async function sendLockAlert(toEmail, username, ip) {
  await transporter.sendMail({
    from:    process.env.SMTP_FROM || 'YaTanDeoSidSai Bank <noreply@ytdss.bank>',
    to:      toEmail,
    subject: '🔒 YaTanDeoSidSai Bank — Account Locked Due to Suspicious Activity',
    html: `
      <div style="font-family:'Segoe UI',sans-serif;max-width:480px;margin:auto;background:#0a0e1a;color:#e8d5b0;border-radius:12px;overflow:hidden;">
        <div style="background:linear-gradient(135deg,#c0392b,#8b0000);padding:24px 32px;text-align:center;">
          <h1 style="margin:0;font-size:22px;letter-spacing:2px;color:#fff;">⚠️ Security Alert</h1>
          <p style="margin:4px 0 0;font-size:12px;opacity:.8;">YaTanDeoSidSai Banking</p>
        </div>
        <div style="padding:32px;">
          <p style="font-size:15px;color:#ff6b6b;">Your account has been <strong>temporarily locked</strong>.</p>
          <p style="color:#aaa;font-size:14px;">We detected <strong>3 consecutive failed login attempts</strong> on your account:</p>
          <div style="background:#111827;border:1px solid #ff6b6b44;border-radius:8px;padding:16px;margin:16px 0;">
            <p style="margin:0;color:#e8d5b0;font-size:14px;"><strong>Username:</strong> ${username}</p>
            <p style="margin:8px 0 0;color:#e8d5b0;font-size:14px;"><strong>IP Address:</strong> ${ip}</p>
            <p style="margin:8px 0 0;color:#e8d5b0;font-size:14px;"><strong>Time:</strong> ${new Date().toUTCString()}</p>
          </div>
          <p style="color:#aaa;font-size:14px;">If this was not you, please contact our security team immediately.</p>
        </div>
        <div style="background:#050810;padding:16px 32px;text-align:center;">
          <p style="color:#555;font-size:12px;margin:0;">© ${new Date().getFullYear()} YaTanDeoSidSai Banking. All rights reserved.</p>
        </div>
      </div>
    `,
  });
}

module.exports = { createOtp, verifyOtp, sendOtpEmail, sendLockAlert };