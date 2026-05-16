// backend/middleware/security.js
'use strict';

const helmet    = require('helmet');
const rateLimit = require('express-rate-limit');
const xss       = require('xss');

const helmetConfig = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:     ["'self'"],
      scriptSrc:      ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      styleSrc:       ["'self'", "https://fonts.googleapis.com", "'unsafe-inline'"],
      fontSrc:        ["'self'", "https://fonts.gstatic.com"],
      imgSrc:         ["'self'", "data:"],
      connectSrc:     ["'self'"],
      frameAncestors: ["'none'"],
      formAction:     ["'self'"],
    },
  },
  hsts:           { maxAge: 31536000, includeSubDomains: true, preload: true },
  xssFilter:      true,
  noSniff:        true,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  frameguard:     { action: 'deny' },
});

const globalLimiter = rateLimit({
  windowMs:       15 * 60 * 1000,
  max:            200,
  standardHeaders: true,
  legacyHeaders:  false,
  message:        { success: false, message: 'Too many requests. Please try again later.' },
});

const authLimiter = rateLimit({
  windowMs:              15 * 60 * 1000,
  max:                   20,
  standardHeaders:       true,
  legacyHeaders:         false,
  message:               { success: false, message: 'Too many authentication attempts. Please wait 15 minutes.' },
  skipSuccessfulRequests: false,
});

const otpLimiter = rateLimit({
  windowMs:       5 * 60 * 1000,
  max:            5,
  standardHeaders: true,
  legacyHeaders:  false,
  message:        { success: false, message: 'Too many OTP requests. Please wait 5 minutes.' },
});

// ─── Attack Pattern Definitions ────────────────────────────────
// FIX: All regex objects are re-created per call (no /g flag on patterns used
//      with .test()) to avoid the stateful lastIndex bug.
const SQL_PATTERNS = [
  /(\bSELECT\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b|\bDROP\b|\bUNION\b|\bTRUNCATE\b)/i,
  /('|--|;|\/\*|\*\/|xp_|exec\b|execute\b|cast\s*\(|convert\s*\()/i,
  /(0x[0-9a-fA-F]+)/,
  /(\bOR\b\s+['"\d]|AND\s+['"\d])/i,
  /(\bSLEEP\s*\(|\bBENCHMARK\s*\(|\bWAITFOR\b)/i,
];

const XSS_PATTERNS = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/i,
  /<[^>]*\bon\w+\s*=/i,
  /javascript\s*:/i,
  /vbscript\s*:/i,
  /data\s*:\s*text\/html/i,
];

// FIX: No /g flag — avoids stateful .lastIndex bug with .test()
const PATH_TRAVERSAL = /(\.\.[/\\]|%2e%2e[/\\%])/i;

function detectAttack(value, fieldName) {
  if (typeof value !== 'string') return null;

  for (const p of SQL_PATTERNS) {
    if (p.test(value)) return `SQL_INJECTION on field: ${fieldName}`;
  }
  for (const p of XSS_PATTERNS) {
    if (p.test(value)) return `XSS_ATTEMPT on field: ${fieldName}`;
  }
  if (PATH_TRAVERSAL.test(value)) return `PATH_TRAVERSAL on field: ${fieldName}`;

  return null;
}

function wafMiddleware(req, res, next) {
  const toCheck = { ...req.body, ...req.query, ...req.params };

  for (const [key, val] of Object.entries(toCheck)) {
    const threat = detectAttack(String(val), key);
    if (threat) {
      console.warn(`[WAF] BLOCKED ${threat} — IP: ${req.ip}`);

      const db = require('../config/db');
      db.query(
        'INSERT INTO security_events (event_type, ip_address, user_agent, details) VALUES ($1, $2, $3, $4)',
        [threat.split(' ')[0], req.ip, req.headers['user-agent'] || '', threat]
      ).catch(() => {});

      return res.status(400).json({
        success: false,
        message:  '⚠️ Malicious input detected. This incident has been logged.',
        blocked:  true,
        threat,
      });
    }
  }
  next();
}

function sanitiseBody(req, _res, next) {
  if (req.body && typeof req.body === 'object') {
    for (const key of Object.keys(req.body)) {
      if (typeof req.body[key] === 'string') {
        req.body[key] = xss(req.body[key].trim());
      }
    }
  }
  next();
}

module.exports = {
  helmetConfig,
  globalLimiter,
  authLimiter,
  otpLimiter,
  wafMiddleware,
  sanitiseBody,
};