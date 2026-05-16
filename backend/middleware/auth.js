// backend/middleware/auth.js
'use strict';

const jwt = require('jsonwebtoken');
require('dotenv').config();

const JWT_SECRET   = process.env.JWT_SECRET || 'change_me_jwt_secret';
const JWT_ISSUER   = 'ytdss-bank';
const JWT_AUDIENCE = 'ytdss-bank-client';

/**
 * requireAuth — protects routes that need a logged-in user.
 * Checks both session AND JWT token for defence-in-depth.
 */
function requireAuth(req, res, next) {
  // 1. Session check
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ success: false, message: 'Unauthorized. Please log in.' });
  }

  // 2. JWT check (from Authorization header or session)
  const token = req.headers['authorization']?.split(' ')[1] || req.session.jwtToken;
  if (!token) {
    req.session.destroy();
    return res.status(401).json({ success: false, message: 'No token provided. Please log in again.' });
  }

  try {
    // FIX: include issuer + audience in verify to match what issueToken signs
    const decoded = jwt.verify(token, JWT_SECRET, {
      issuer:   JWT_ISSUER,
      audience: JWT_AUDIENCE,
    });

    // Ensure token matches session user
    if (decoded.userId !== req.session.userId) {
      req.session.destroy();
      return res.status(401).json({ success: false, message: 'Session mismatch. Please log in again.' });
    }

    req.user = decoded;
    next();
  } catch (err) {
    req.session.destroy();
    return res.status(401).json({ success: false, message: 'Token expired or invalid. Please log in again.' });
  }
}

/**
 * requireRole — RBAC middleware.
 * Must be used AFTER requireAuth.
 */
function requireRole(role) {
  return [
    requireAuth,
    (req, res, next) => {
      if (req.user && req.user.role === role) {
        next();
      } else {
        return res.status(403).json({ success: false, message: 'Forbidden. Insufficient permissions.' });
      }
    }
  ];
}

/**
 * issueToken — creates a signed JWT for a user.
 */
function issueToken(userId, username, role = 'user') {
  return jwt.sign(
    { userId, username, role },
    JWT_SECRET,
    {
      expiresIn: '30m',
      issuer:    JWT_ISSUER,
      audience:  JWT_AUDIENCE,
    }
  );
}

module.exports = { requireAuth, requireRole, issueToken };