// backend/middleware/session.js
'use strict';

const session = require('express-session');
require('dotenv').config();

const isProd = process.env.NODE_ENV === 'production';

// FIX: The __Host- cookie prefix requires:
//   1. secure: true  (always — even in dev, or drop the prefix in dev)
//   2. path: '/'     (explicit)
//   3. No Domain attribute
// We use the prefix only in production where HTTPS is guaranteed.
// In development, a plain name is used so the app still works over HTTP.
const cookieName = isProd ? '__Host-ytdss_sid' : 'ytdss_sid';

const sessionConfig = session({
  secret:            process.env.SESSION_SECRET || 'change_me_in_production',
  name:              cookieName,
  resave:            false,
  saveUninitialized: false,
  rolling:           true,
  cookie: {
    httpOnly: true,
    secure:   isProd,          // HTTPS only in prod; HTTP allowed in dev
    sameSite: 'strict',        // CSRF mitigation
    path:     '/',             // Required for __Host- prefix
    maxAge:   30 * 60 * 1000,  // 30 minutes
  },
});

module.exports = { sessionConfig };