# YaTanDeoSidSai Banking 🏦

> **A security-first, full-stack web banking application** for education loan management — built with Node.js, Express.js, and PostgreSQL.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
  - [Environment Variables](#environment-variables)
  - [Database Setup](#database-setup)
  - [Running the App](#running-the-app)
- [Authentication Flow](#authentication-flow)
- [API Reference](#api-reference)
- [Security Architecture](#security-architecture)
- [Pages & UI](#pages--ui)
- [Email Notifications](#email-notifications)
- [File Uploads](#file-uploads)

---

## Overview

YaTanDeoSidSai Banking is a production-grade banking web application focused on **education loan management**. It demonstrates a layered, defence-in-depth security model — combining multi-factor authentication, CSRF protection, a custom WAF, AES-256-GCM encryption, and role-based access control across three distinct portals:

- **Public Landing Page** — Marketing and navigation
- **User Dashboard** — Education loan application and history
- **Admin Panel** — Loan review and status management

---

## Features

### Authentication
- Two-factor login: **Password + Email OTP**
- Email-verified account registration
- Three-step password reset via OTP
- Account lockout after **3 consecutive failed attempts** with email security alert
- OTP resend capability with automatic invalidation of previous codes
- Rolling session with **30-minute idle timeout**

### Loan Management
- Education loan application form with file upload (collateral documents)
- Application history view per user
- Admin panel to view all applications and update statuses (pending / approved / rejected)
- Annual income stored **AES-256-GCM encrypted** at rest

### Security
- Custom Web Application Firewall (WAF) blocking SQL injection, XSS, and path traversal
- CSRF token protection on all state-changing endpoints
- Helmet.js HTTP security headers (CSP, HSTS, X-Frame-Options, etc.)
- Three-tier rate limiting (global, auth, OTP)
- bcrypt password hashing (12 rounds)
- Cache-Control headers preventing BFCache post-logout access
- Immutable security event audit log in the database

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js |
| Framework | Express.js |
| Database | PostgreSQL (via `pg` pool) |
| Authentication | express-session + jsonwebtoken + OTP |
| Password Hashing | bcryptjs (12 rounds) |
| Encryption | Node.js `crypto` — AES-256-GCM |
| Email | nodemailer (SMTP / Gmail) |
| File Uploads | multer |
| Security Headers | helmet |
| CSRF | csurf |
| Rate Limiting | express-rate-limit |
| Input Validation | express-validator |
| XSS Sanitisation | xss |
| Frontend | Vanilla HTML5 / CSS3 / JavaScript |

---

## Project Structure

```
project-root/
├── backend/
│   ├── server.js                  # App entry point, middleware chain, page routes
│   ├── config/
│   │   └── db.js                  # PostgreSQL connection pool
│   ├── middleware/
│   │   ├── auth.js                # requireAuth, requireRole, issueToken
│   │   ├── security.js            # Helmet, rate limiters, WAF, sanitiseBody
│   │   ├── session.js             # express-session config
│   │   └── upload.js              # multer secure file upload
│   ├── routes/
│   │   ├── auth.routes.js         # /api/auth/* endpoints
│   │   ├── loan.routes.js         # /api/loan/* endpoints
│   │   └── admin.routes.js        # /api/admin/* endpoints
│   └── utils/
│       ├── crypto.js              # AES-256-GCM encrypt / decrypt
│       ├── otp.js                 # OTP generation, storage, verification, email
│       ├── password.js            # Policy validation, bcrypt hash/compare
│       └── sanitize.js            # express-validator field validators
│
├── frontend/
│   ├── index.html                 # Public landing page
│   ├── css/
│   │   └── styles.css             # Unified design system
│   ├── js/
│   │   ├── security.js            # CSRF token fetch, escapeHTML, showThreat
│   │   ├── auth.js                # Login, register, OTP, forgot/reset flows
│   │   ├── dashboard.js           # Loan form submission, logout
│   │   └── admin.js               # Loan table, status updates, logout
│   └── pages/
│       ├── login.html
│       ├── register.html
│       ├── forgot.html
│       ├── dashboard.html
│       └── admin.html
│
└── database/
    └── schema.sql                 # PostgreSQL schema — run once to initialise
```

---

## Getting Started

### Prerequisites

- **Node.js** v18 or higher
- **PostgreSQL** v14 or higher
- An SMTP account (Gmail with App Password works out of the box)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/ytdss-banking.git
cd ytdss-banking

# Install backend dependencies
cd backend
npm install
```

### Environment Variables

Create a `.env` file inside the `backend/` directory:

```env
# Server
PORT=3000
NODE_ENV=development          # Set to 'production' for HTTPS + __Host- cookie prefix

# Security
SESSION_SECRET=your_strong_random_session_secret
JWT_SECRET=your_strong_random_jwt_secret
ENCRYPTION_KEY=64_char_hex_string_for_aes256   # Generate: node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# Database
DB_HOST=localhost
DB_PORT=5432
DB_USER=postgres
DB_PASSWORD=your_db_password
DB_NAME=ytdss_bank

# Email (SMTP)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_gmail_app_password
SMTP_FROM=YaTanDeoSidSai Bank <noreply@ytdss.bank>

# OTP
OTP_TTL_MINUTES=5
```

> **Generating a secure ENCRYPTION_KEY:**
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

### Database Setup

```bash
# Create the database
psql -U postgres -c "CREATE DATABASE ytdss_bank;"

# Run the schema
psql -U postgres -d ytdss_bank -f database/schema.sql
```

To create an admin user, insert one directly after registration:

```sql
UPDATE users SET role = 'admin' WHERE username = 'your_username';
```

### Running the App

```bash
# From the backend/ directory
node server.js

# Or with auto-restart during development
npx nodemon server.js
```

The application will be available at **http://localhost:3000**

---

## Authentication Flow

### Registration
1. User submits registration form (first name, last name, username, email, password)
2. Backend validates fields, checks for duplicates, hashes password with bcrypt (12 rounds)
3. Account created with `is_verified = false`
4. 6-digit OTP emailed to the user
5. User submits OTP → account activated

### Login (Two-Factor)
1. User submits username + password
2. Backend verifies credentials and account state (verified, not locked)
3. Login OTP emailed to user
4. User submits OTP → session created, JWT (30 min) issued and stored in session
5. User redirected based on role (`/dashboard` or `/admin`)

> After **3 failed login attempts**, the account is locked and a security alert email is sent to the registered address.

### Password Reset
1. User enters their username on the `/forgot` page
2. Password reset OTP emailed
3. User verifies OTP
4. User sets a new password meeting the policy requirements

---

## API Reference

All endpoints are prefixed with `/api`. State-changing routes require an `x-csrf-token` header (fetch from `GET /api/auth/csrf-token` first).

### Auth Routes — `/api/auth`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/csrf-token` | None | Fetch a CSRF token |
| `POST` | `/register` | None | Create a new user account |
| `POST` | `/verify-register` | None | Activate account via OTP |
| `POST` | `/login` | None | Step 1 — password check |
| `POST` | `/verify-login` | None | Step 2 — OTP check + session issue |
| `POST` | `/logout` | Session | Destroy session |
| `POST` | `/forgot-password` | None | Initiate password reset |
| `POST` | `/verify-forgot` | None | Verify identity OTP |
| `POST` | `/reset-password` | Session (temp) | Set new password |
| `POST` | `/resend-otp` | None | Re-send OTP for any purpose |

### Loan Routes — `/api/loan`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `POST` | `/apply` | JWT + Session | Submit a loan application |
| `GET` | `/history` | JWT + Session | Get current user's applications |

### Admin Routes — `/api/admin`

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| `GET` | `/loans` | Admin Role | Fetch all applications (income decrypted) |
| `POST` | `/loans/:id/status` | Admin Role | Update loan status |

---

## Security Architecture

### Layers at a Glance

```
Request
  │
  ├─ Helmet.js           → HTTP security headers (CSP, HSTS, X-Frame-Options, ...)
  ├─ Global Rate Limiter → 200 req / 15 min per IP
  ├─ Session Middleware   → Cookie: httpOnly, sameSite=strict, secure (prod)
  ├─ CSRF Protection      → csurf (session-stored token, not cookie)
  ├─ WAF                 → Blocks SQLi, XSS patterns, path traversal
  ├─ sanitiseBody        → xss() library over all string body fields
  ├─ Cache-Control       → no-store on every response (prevents BFCache)
  │
  └─ Route Handler
       ├─ requireAuth     → Session + JWT dual check
       ├─ requireRole     → RBAC (user / admin)
       ├─ express-validator → Field-level validation chains
       ├─ bcrypt          → Password hash/compare
       └─ AES-256-GCM     → Sensitive field encryption at rest
```

### Password Policy

Passwords must contain:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character (`!@#$%^&*` etc.)

### WAF Patterns Detected

| Category | Examples Detected |
|---|---|
| SQL Injection | `SELECT`, `UNION`, `DROP`, `--`, `SLEEP()`, `0x...` |
| XSS | `<script>`, `onclick=`, `javascript:`, `data:text/html` |
| Path Traversal | `../`, `%2e%2e/` |

All blocked requests are logged to the `security_events` database table.

---

## Pages & UI

| URL | Page | Access |
|---|---|---|
| `/` | Landing Page | Public |
| `/login` | Sign In | Public |
| `/register` | Registration | Public |
| `/forgot` | Password Recovery | Public |
| `/dashboard` | User Dashboard | Authenticated users |
| `/admin` | Admin Panel | Admin role only |

The UI uses a **dark luxury banking aesthetic** — deep navy backgrounds, gold accents, glassmorphism cards (`backdrop-filter: blur`), and Google Fonts (Outfit + Inter). All pages are responsive with a breakpoint at 900px.

---

## Email Notifications

Emails are sent via nodemailer with a branded HTML template. Four email types are in use:

| Trigger | Email Sent |
|---|---|
| Account registered | Registration OTP (5-minute expiry) |
| Login credentials verified | Login OTP (5-minute expiry) |
| Forgot password initiated | Password reset OTP (5-minute expiry) |
| 3 consecutive failed logins | Account lock security alert with IP and timestamp |

---

## File Uploads

Collateral documents for loan applications are accepted with the following restrictions:

| Rule | Value |
|---|---|
| Allowed types | PDF, PNG, JPEG |
| Maximum size | 2 MB |
| Max files per request | 1 |
| Filename on disk | 16-byte random hex + original extension |

The original filename is always discarded. Files are stored in an `uploads/` directory at the project root (outside the web server's static path).

---

> **YaTanDeoSidSai Banking** — *Secure. Trusted. Elite.*
