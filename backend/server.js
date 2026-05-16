// backend/server.js
'use strict';

const express      = require('express');
const path         = require('path');
const cookieParser = require('cookie-parser');
const csrf         = require('csurf');
require('dotenv').config();

const { sessionConfig }                                          = require('./middleware/session');
const { helmetConfig, globalLimiter, wafMiddleware, sanitiseBody } = require('./middleware/security');
const authRoutes = require('./routes/auth.routes');
const loanRoutes = require('./routes/loan.routes');
const adminRoutes = require('./routes/admin.routes');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── Core middleware (order matters) ──────────────────────────
app.use(helmetConfig);
app.use(globalLimiter);
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());
app.use(sessionConfig);

// FIX: WAF + sanitise run once, globally, BEFORE routes.
//      Route-level wafMiddleware calls were REMOVED from route files
//      to prevent double-scanning. The global application here is sufficient.
app.use(wafMiddleware);
app.use(sanitiseBody);

// ─── Cache-Control Middleware ─────────────────────────────────
// Prevent BFCache from storing sensitive pages and back-button access
const noCache = (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
};
app.use(noCache);

// ─── Static assets ────────────────────────────────────────────
app.use(express.static(path.join(__dirname, '../frontend')));

// ─── CSRF setup ───────────────────────────────────────────────
const csrfProtection = csrf({ cookie: false }); // uses session

// FIX: CSRF token endpoint must NOT itself be behind csrfProtection —
//      it is a GET that ISSUES the token, not a state-changing request.
//      Mounting it before the protected router solves the chicken-and-egg problem.
app.get('/api/auth/csrf-token', csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ─── API Routes (all state-changing routes protected by CSRF) ─
app.use('/api/auth', csrfProtection, authRoutes);
app.use('/api/loan', csrfProtection, loanRoutes);
app.use('/api/admin', csrfProtection, adminRoutes);

// ─── Page Auth Middleware ─────────────────────────────────────
const requirePageAuth = (req, res, next) => {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  next();
};

const requirePageAdmin = (req, res, next) => {
  if (!req.session || !req.session.userId) return res.redirect('/login');
  if (req.session.role !== 'admin') return res.redirect('/dashboard');
  next();
};

// ─── Page Routes ──────────────────────────────────────────────
app.get('/',          (_req, res) => res.sendFile(path.join(__dirname, '../frontend/index.html')));
app.get('/login',     (_req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/login.html')));
app.get('/register',  (_req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/register.html')));
app.get('/forgot',    (_req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/forgot.html')));
app.get('/dashboard', requirePageAuth, (_req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/dashboard.html')));
app.get('/admin',     requirePageAdmin, (_req, res) => res.sendFile(path.join(__dirname, '../frontend/pages/admin.html')));

// ─── 404 handler ──────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ success: false, message: 'Resource not found.' });
});

// ─── Global error handler ─────────────────────────────────────
app.use((err, req, res, _next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.warn(`[CSRF] BLOCKED — IP: ${req.ip}`);
    return res.status(403).json({ success: false, message: '⚠️ CSRF Attack Blocked! Invalid security token.' });
  }
  console.error('[SERVER ERROR]', err);
  res.status(500).json({ success: false, message: 'An internal server error occurred.' });
});

app.listen(PORT, () => {
  console.log(`[SERVER] YaTanDeoSidSai Bank running on http://localhost:${PORT}`);
});