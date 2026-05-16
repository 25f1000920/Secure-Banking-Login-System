-- ============================================================
-- YaTanDeoSidSai Banking — Database Schema (PostgreSQL)
-- Run: psql -U postgres -d ytdss_bank -f database/schema.sql
-- ============================================================

-- Create database manually if not exists (psql doesn't support CREATE DATABASE IF NOT EXISTS simply)
-- CREATE DATABASE ytdss_bank;
-- \c ytdss_bank;

-- ─── Users ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS users (
  id              SERIAL PRIMARY KEY,
  first_name      VARCHAR(64) NOT NULL,
  last_name       VARCHAR(64) NOT NULL,
  username        VARCHAR(64) NOT NULL UNIQUE,
  email           VARCHAR(255) NOT NULL UNIQUE,
  password_hash   VARCHAR(255) NOT NULL,
  role            VARCHAR(20) NOT NULL DEFAULT 'user',
  is_verified     BOOLEAN NOT NULL DEFAULT false,
  is_locked       BOOLEAN NOT NULL DEFAULT false,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_at       TIMESTAMP DEFAULT NULL,
  last_login      TIMESTAMP DEFAULT NULL,
  created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_username ON users (username);
CREATE INDEX IF NOT EXISTS idx_email ON users (email);

-- ─── OTP Store ───────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS otps (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  otp_code    CHAR(6) NOT NULL,
  purpose     VARCHAR(50) NOT NULL CHECK (purpose IN ('login_verify', 'register_verify', 'forgot_password')),
  expires_at  TIMESTAMP NOT NULL,
  used        BOOLEAN NOT NULL DEFAULT false,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_purpose ON otps (user_id, purpose);

-- ─── Sessions (optional server-side store) ───────────────────
CREATE TABLE IF NOT EXISTS user_sessions (
  sid         VARCHAR(255) PRIMARY KEY,
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip_address  VARCHAR(45) DEFAULT NULL,
  user_agent  VARCHAR(512) DEFAULT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at  TIMESTAMP NOT NULL
);

-- ─── Security Events Log ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS security_events (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER DEFAULT NULL,
  event_type  VARCHAR(64) NOT NULL,
  ip_address  VARCHAR(45) DEFAULT NULL,
  user_agent  VARCHAR(512) DEFAULT NULL,
  details     TEXT DEFAULT NULL,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_event_user_id ON security_events (user_id);
CREATE INDEX IF NOT EXISTS idx_event_type ON security_events (event_type);

-- ─── Loan Applications ───────────────────────────────────────
CREATE TABLE IF NOT EXISTS loan_applications (
  id                SERIAL PRIMARY KEY,
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  applicant_name    VARCHAR(128) NOT NULL,
  loan_amount       DECIMAL(12,2) NOT NULL,
  loan_purpose      VARCHAR(512) NOT NULL,
  institution_name  VARCHAR(256) NOT NULL,
  course_name       VARCHAR(256) NOT NULL,
  course_duration   VARCHAR(64) NOT NULL,
  annual_income     VARCHAR(512) NOT NULL, -- Changed to VARCHAR for encryption
  collateral        VARCHAR(512) DEFAULT NULL,
  collateral_file   VARCHAR(255) DEFAULT NULL, -- Path to uploaded file
  status            VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'rejected')),
  submitted_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_loan_user_id ON loan_applications (user_id);

-- ─── Function: increment_failed_attempts ─────────────────────
CREATE OR REPLACE FUNCTION increment_failed_attempts(p_user_id INTEGER)
RETURNS VOID AS $$
BEGIN
  UPDATE users
  SET
    failed_attempts = failed_attempts + 1,
    is_locked       = CASE WHEN failed_attempts + 1 >= 3 THEN true ELSE false END,
    locked_at       = CASE WHEN failed_attempts + 1 >= 3 THEN NOW() ELSE locked_at END
  WHERE id = p_user_id;
END;
$$ LANGUAGE plpgsql;