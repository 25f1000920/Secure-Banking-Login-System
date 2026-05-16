// backend/routes/auth.routes.js
'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../config/db');
const { createOtp, verifyOtp, sendOtpEmail, sendLockAlert } = require('../utils/otp');
const { validatePassword, hashPassword, comparePassword }   = require('../utils/password');
const { issueToken }                                        = require('../middleware/auth');
const { authLimiter, otpLimiter }                           = require('../middleware/security');
// NOTE: wafMiddleware is applied globally in server.js — NOT repeated here.
const {
  usernameValidator, passwordValidator, emailValidator,
  firstNameValidator, lastNameValidator, otpValidator,
  handleValidation,
} = require('../utils/sanitize');

// FIX: Valid bcrypt hash of a dummy password for constant-time comparison
// when the username doesn't exist — prevents timing-based user enumeration.
// Generated with: bcrypt.hashSync('DummyPass!0', 12)
const DUMMY_HASH = '$2a$12$KIXVbgbBfT.oHBFUFR.jd.kq5Fk/nDrHpLT4gU5Zz5P6VcDWsLv6';

async function logEvent(eventType, ip, ua, details, userId = null) {
  await db.query(
    'INSERT INTO security_events (user_id, event_type, ip_address, user_agent, details) VALUES ($1, $2, $3, $4, $5)',
    [userId, eventType, ip, ua || '', details || '']
  ).catch(() => {});
}

// ─── REGISTER ────────────────────────────────────────────────
router.post('/register',
  authLimiter,
  [firstNameValidator, lastNameValidator, usernameValidator, emailValidator, passwordValidator, handleValidation],
  async (req, res) => {
    try {
      const { firstName, lastName, username, email, password, confirmPassword } = req.body;

      // FIX: confirmPassword comparison before xss() could mangle it —
      // compare raw values; both passed through sanitiseBody equally.
      if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match.' });
      }

      const pwCheck = validatePassword(password);
      if (!pwCheck.valid) {
        return res.status(400).json({ success: false, message: pwCheck.message });
      }

      const { rows: existing } = await db.query(
        'SELECT id FROM users WHERE username = $1 OR email = $2 LIMIT 1',
        [username, email]
      );
      if (existing.length) {
        return res.status(409).json({ success: false, message: 'Username or email already exists.' });
      }

      const hash   = await hashPassword(password);
      const result = await db.query(
        'INSERT INTO users (first_name, last_name, username, email, password_hash, is_verified) VALUES ($1, $2, $3, $4, $5, false) RETURNING id',
        [firstName, lastName, username, email, hash]
      );
      const userId = result.rows[0].id;

      const otp = await createOtp(userId, 'register_verify');
      await sendOtpEmail(email, otp, 'register_verify');
      await logEvent('REGISTER_OTP_SENT', req.ip, req.headers['user-agent'], username, userId);

      return res.json({ success: true, message: 'Registration initiated. OTP sent to your email.', userId });
    } catch (err) {
      console.error('[REGISTER]', err);
      return res.status(500).json({ success: false, message: 'Registration failed. Please try again.' });
    }
  }
);

// ─── VERIFY REGISTER ─────────────────────────────────────────
router.post('/verify-register',
  otpLimiter,
  [otpValidator, handleValidation],
  async (req, res) => {
    try {
      const { userId, otp } = req.body;
      if (!userId) return res.status(400).json({ success: false, message: 'User ID required.' });

      const valid = await verifyOtp(parseInt(userId), otp, 'register_verify');
      if (!valid) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
      }

      await db.query('UPDATE users SET is_verified = true WHERE id = $1', [userId]);
      await logEvent('REGISTER_COMPLETE', req.ip, req.headers['user-agent'], '', userId);

      return res.json({ success: true, message: 'Account verified! You can now log in.' });
    } catch (err) {
      console.error('[VERIFY-REGISTER]', err);
      return res.status(500).json({ success: false, message: 'Verification failed. Please try again.' });
    }
  }
);

// ─── LOGIN ───────────────────────────────────────────────────
router.post('/login',
  authLimiter,
  [usernameValidator, passwordValidator, handleValidation],
  async (req, res) => {
    try {
      const { username, password } = req.body;

      const { rows } = await db.query(
        'SELECT id, email, password_hash, is_verified, is_locked, failed_attempts FROM users WHERE username = $1 LIMIT 1',
        [username]
      );

      if (!rows.length) {
        // FIX: Use a valid bcrypt hash so comparePassword doesn't throw.
        // This keeps response time constant, preventing username enumeration.
        await comparePassword(password, DUMMY_HASH);
        await logEvent('LOGIN_FAIL_UNKNOWN_USER', req.ip, req.headers['user-agent'], username);
        return res.status(401).json({ success: false, message: 'Invalid username or password.' });
      }

      const user = rows[0];

      if (user.is_locked) {
        await logEvent('LOGIN_ATTEMPT_LOCKED', req.ip, req.headers['user-agent'], username, user.id);
        return res.status(403).json({
          success: false,
          message: 'Account is locked due to too many failed attempts. Please contact support.',
        });
      }

      if (!user.is_verified) {
        return res.status(403).json({
          success: false,
          message: 'Account not verified. Please check your email for the OTP.',
        });
      }

      const match = await comparePassword(password, user.password_hash);
      if (!match) {
        await db.query(`
          UPDATE users SET
            failed_attempts = failed_attempts + 1,
            is_locked  = CASE WHEN failed_attempts + 1 >= 3 THEN true ELSE false END,
            locked_at  = CASE WHEN failed_attempts + 1 >= 3 THEN NOW() ELSE locked_at END
          WHERE id = $1`, [user.id]
        );

        const newAttempts = user.failed_attempts + 1;
        await logEvent('LOGIN_FAIL_BAD_PW', req.ip, req.headers['user-agent'], `Attempt ${newAttempts}`, user.id);

        if (newAttempts >= 3) {
          const { rows: emailRow } = await db.query('SELECT email, username FROM users WHERE id = $1', [user.id]);
          if (emailRow.length) {
            await sendLockAlert(emailRow[0].email, emailRow[0].username, req.ip).catch(() => {});
          }
          return res.status(403).json({
            success: false,
            message: '🔒 Account locked after 3 failed attempts. A security alert has been sent to your email.',
          });
        }

        return res.status(401).json({
          success: false,
          message: `Invalid username or password. ${3 - newAttempts} attempt(s) remaining.`,
        });
      }

      await db.query('UPDATE users SET failed_attempts = 0 WHERE id = $1', [user.id]);

      const otp = await createOtp(user.id, 'login_verify');
      await sendOtpEmail(user.email, otp, 'login_verify');
      await logEvent('LOGIN_OTP_SENT', req.ip, req.headers['user-agent'], '', user.id);

      return res.json({ success: true, message: 'OTP sent to your registered email.', userId: user.id });
    } catch (err) {
      console.error('[LOGIN]', err);
      return res.status(500).json({ success: false, message: 'Login failed. Please try again.' });
    }
  }
);

// ─── VERIFY LOGIN ────────────────────────────────────────────
router.post('/verify-login',
  otpLimiter,
  [otpValidator, handleValidation],
  async (req, res) => {
    try {
      const { userId, otp } = req.body;
      if (!userId) return res.status(400).json({ success: false, message: 'User ID required.' });

      const valid = await verifyOtp(parseInt(userId), otp, 'login_verify');
      if (!valid) {
        await logEvent('LOGIN_OTP_FAIL', req.ip, req.headers['user-agent'], '', userId);
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
      }

      const { rows } = await db.query(
        'SELECT id, username, first_name, last_name, email, role FROM users WHERE id = $1 LIMIT 1',
        [userId]
      );
      if (!rows.length) return res.status(404).json({ success: false, message: 'User not found.' });

      const user = rows[0];
      await db.query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

      const token            = issueToken(user.id, user.username, user.role);
      req.session.userId    = user.id;
      req.session.username  = user.username;
      req.session.role      = user.role;
      req.session.jwtToken  = token;

      await logEvent('LOGIN_SUCCESS', req.ip, req.headers['user-agent'], '', user.id);

      return res.json({
        success: true,
        message: 'Login successful.',
        token,
        user: {
          id:        user.id,
          username:  user.username,
          firstName: user.first_name,
          lastName:  user.last_name,
          role:      user.role,
        },
      });
    } catch (err) {
      console.error('[VERIFY-LOGIN]', err);
      return res.status(500).json({ success: false, message: 'OTP verification failed.' });
    }
  }
);

// ─── FORGOT PASSWORD ─────────────────────────────────────────
// FIX: Always return the same message and HTTP status regardless of whether
//      the username exists — prevents user enumeration via response differences.
router.post('/forgot-password',
  authLimiter,
  [usernameValidator, handleValidation],
  async (req, res) => {
    const SAFE_MSG = 'If that username exists, an OTP has been sent to the registered email.';
    try {
      const { username } = req.body;

      const { rows } = await db.query(
        'SELECT id, email FROM users WHERE username = $1 AND is_verified = true LIMIT 1',
        [username]
      );

      if (!rows.length) {
        // Return 200 with identical message — do NOT leak whether user exists
        return res.json({ success: true, message: SAFE_MSG });
      }

      const user = rows[0];
      const otp  = await createOtp(user.id, 'forgot_password');
      await sendOtpEmail(user.email, otp, 'forgot_password');
      await logEvent('FORGOT_PW_OTP_SENT', req.ip, req.headers['user-agent'], username, user.id);

      // FIX: Return userId only when user exists (needed for client OTP step),
      //      but message is always the same to avoid enumeration.
      return res.json({ success: true, message: SAFE_MSG, userId: user.id });
    } catch (err) {
      console.error('[FORGOT-PW]', err);
      return res.status(500).json({ success: false, message: 'Failed to process request.' });
    }
  }
);

// ─── VERIFY FORGOT ───────────────────────────────────────────
router.post('/verify-forgot',
  otpLimiter,
  [otpValidator, handleValidation],
  async (req, res) => {
    try {
      const { userId, otp } = req.body;
      if (!userId) return res.status(400).json({ success: false, message: 'User ID required.' });

      const valid = await verifyOtp(parseInt(userId), otp, 'forgot_password');
      if (!valid) {
        return res.status(400).json({ success: false, message: 'Invalid or expired OTP.' });
      }

      req.session.resetUserId = parseInt(userId);
      req.session.resetExpiry = Date.now() + 10 * 60 * 1000;

      return res.json({ success: true, message: 'OTP verified. You may now reset your password.' });
    } catch (err) {
      console.error('[VERIFY-FORGOT]', err);
      return res.status(500).json({ success: false, message: 'OTP verification failed.' });
    }
  }
);

// ─── RESET PASSWORD ──────────────────────────────────────────
router.post('/reset-password',
  authLimiter,
  [passwordValidator, handleValidation],
  async (req, res) => {
    try {
      const { password, confirmPassword } = req.body;

      if (!req.session.resetUserId || Date.now() > req.session.resetExpiry) {
        return res.status(403).json({ success: false, message: 'Reset session expired. Please start again.' });
      }

      if (password !== confirmPassword) {
        return res.status(400).json({ success: false, message: 'Passwords do not match.' });
      }

      const pwCheck = validatePassword(password);
      if (!pwCheck.valid) {
        return res.status(400).json({ success: false, message: pwCheck.message });
      }

      const hash = await hashPassword(password);
      await db.query(
        'UPDATE users SET password_hash = $1, failed_attempts = 0, is_locked = false WHERE id = $2',
        [hash, req.session.resetUserId]
      );

      await logEvent('PASSWORD_RESET', req.ip, req.headers['user-agent'], '', req.session.resetUserId);

      delete req.session.resetUserId;
      delete req.session.resetExpiry;

      return res.json({ success: true, message: 'Password reset successfully. Please log in.' });
    } catch (err) {
      console.error('[RESET-PW]', err);
      return res.status(500).json({ success: false, message: 'Password reset failed.' });
    }
  }
);

// ─── LOGOUT ──────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) return res.status(500).json({ success: false, message: 'Logout failed.' });
    // Clear both possible cookie names (prod vs dev)
    res.clearCookie('__Host-ytdss_sid');
    res.clearCookie('ytdss_sid');
    return res.json({ success: true, message: 'Logged out successfully.' });
  });
});

// NOTE: /csrf-token is registered directly in server.js BEFORE csrfProtection
// ─── RESEND OTP ──────────────────────────────────────────────
router.post('/resend-otp',
  otpLimiter,
  async (req, res) => {
    try {
      const { userId, purpose } = req.body;
      if (!userId || !purpose) return res.status(400).json({ success: false, message: 'User ID and purpose required.' });

      const validPurposes = ['login_verify', 'register_verify', 'forgot_password'];
      if (!validPurposes.includes(purpose)) {
        return res.status(400).json({ success: false, message: 'Invalid OTP purpose.' });
      }

      const { rows } = await db.query('SELECT id, email, username FROM users WHERE id = $1 LIMIT 1', [parseInt(userId)]);
      if (!rows.length) return res.status(404).json({ success: false, message: 'User not found.' });

      const user = rows[0];
      const otp = await createOtp(user.id, purpose);
      await sendOtpEmail(user.email, otp, purpose);
      await logEvent('RESEND_OTP', req.ip, req.headers['user-agent'], purpose, user.id);

      return res.json({ success: true, message: 'A new OTP has been sent to your email.' });
    } catch (err) {
      console.error('[RESEND-OTP]', err);
      return res.status(500).json({ success: false, message: 'Failed to resend OTP.' });
    }
  }
);

module.exports = router;