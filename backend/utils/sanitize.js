// backend/utils/sanitize.js
'use strict';

const { body, validationResult } = require('express-validator');

// ─── Field Validators ─────────────────────────────────────────

const usernameValidator = body('username')
  .trim()
  .notEmpty().withMessage('Username is required.')
  .isLength({ min: 3, max: 32 }).withMessage('Username must be 3–32 characters.')
  .matches(/^[a-zA-Z0-9_.-]+$/).withMessage('Username may only contain letters, numbers, _ . -');

const passwordValidator = body('password')
  .notEmpty().withMessage('Password is required.')
  .isLength({ min: 8, max: 128 }).withMessage('Password must be 8–128 characters.');

const emailValidator = body('email')
  .trim()
  .notEmpty().withMessage('Email is required.')
  .isEmail().withMessage('Enter a valid email address.')
  .normalizeEmail();

const firstNameValidator = body('firstName')
  .trim()
  .notEmpty().withMessage('First name is required.')
  .isLength({ max: 64 }).withMessage('First name too long.')
  .matches(/^[a-zA-Z\s'-]+$/).withMessage('First name contains invalid characters.');

const lastNameValidator = body('lastName')
  .trim()
  .notEmpty().withMessage('Last name is required.')
  .isLength({ max: 64 }).withMessage('Last name too long.')
  .matches(/^[a-zA-Z\s'-]+$/).withMessage('Last name contains invalid characters.');

const otpValidator = body('otp')
  .trim()
  .notEmpty().withMessage('OTP is required.')
  .matches(/^\d{6}$/).withMessage('OTP must be exactly 6 digits.');

// ─── Validation Result Handler ────────────────────────────────
function handleValidation(req, res, next) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({
      success: false,
      message: errors.array()[0].msg,
      errors: errors.array(),
    });
  }
  next();
}

module.exports = {
  usernameValidator,
  passwordValidator,
  emailValidator,
  firstNameValidator,
  lastNameValidator,
  otpValidator,
  handleValidation,
};