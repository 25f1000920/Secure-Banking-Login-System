// backend/config/db.js
'use strict';

const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({
  host:                process.env.DB_HOST     || 'localhost',
  port:                parseInt(process.env.DB_PORT) || 5432,
  user:                process.env.DB_USER     || 'postgres',
  password:            process.env.DB_PASSWORD || '',
  database:            process.env.DB_NAME     || 'ytdss_bank',
  max:                 10,
  idleTimeoutMillis:   30000,
  connectionTimeoutMillis: 5000,
});

// Verify connection on startup
(async () => {
  try {
    const client = await pool.connect();
    console.log('[DB] PostgreSQL connected successfully.');
    client.release();
  } catch (err) {
    console.error('[DB] Connection failed:', err.message);
    process.exit(1);
  }
})();

// Pool error handler — prevents unhandled rejection crashes
pool.on('error', (err) => {
  console.error('[DB] Unexpected pool error:', err.message);
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};