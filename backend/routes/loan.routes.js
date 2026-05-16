// backend/routes/loan.routes.js
'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../config/db');
const { requireAuth } = require('../middleware/auth');
const { secureUpload } = require('../middleware/upload');
const { encrypt } = require('../utils/crypto');
const { body, validationResult, matchedData } = require('express-validator');
const { wafMiddleware, sanitiseBody } = require('../middleware/security');



router.post('/apply',
  requireAuth,
  secureUpload('collateral_file'),
  wafMiddleware,
  sanitiseBody,
  [
    body('applicantName').trim().escape().notEmpty().withMessage('Applicant name is required.'),
    body('loanAmount').isNumeric().withMessage('Loan amount must be a valid number.'),
    body('loanPurpose').trim().escape().notEmpty().withMessage('Loan purpose is required.'),
    body('institutionName').trim().escape().notEmpty().withMessage('Institution name is required.'),
    body('courseName').trim().escape().notEmpty().withMessage('Course name is required.'),
    body('courseDuration').trim().escape().notEmpty(),
    body('annualIncome').isNumeric().withMessage('Annual income must be a valid number.'),
    body('collateral').optional().trim().escape()
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(422).json({ success: false, message: errors.array()[0].msg });
    }

    try {
      const { 
        applicantName, loanAmount, loanPurpose, institutionName, 
        courseName, courseDuration, annualIncome, collateral 
      } = matchedData(req);
      
      const encryptedIncome = encrypt(annualIncome);
      const collateralFile = req.file ? req.file.filename : null;
      
      await db.query(
        `INSERT INTO loan_applications 
        (user_id, applicant_name, loan_amount, loan_purpose, institution_name, course_name, course_duration, annual_income, collateral, collateral_file) 
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [req.session.userId, applicantName, loanAmount, loanPurpose, institutionName, courseName, courseDuration, encryptedIncome, collateral || 'None', collateralFile]
      );

      res.json({ success: true, message: 'Education Loan Application submitted successfully.' });
    } catch (err) {
      console.error('[LOAN APPLY]', err);
      res.status(500).json({ success: false, message: 'Failed to submit application due to a server error.' });
    }
  }
);

router.get('/history', requireAuth, async (req, res) => {
    try {
        const { rows } = await db.query(
            'SELECT id, applicant_name, loan_amount, status, submitted_at FROM loan_applications WHERE user_id = $1 ORDER BY submitted_at DESC',
            [req.session.userId]
        );
        res.json({ success: true, applications: rows });
    } catch (err) {
        console.error('[LOAN HISTORY]', err);
        res.status(500).json({ success: false, message: 'Failed to fetch loan history.' });
    }
});

module.exports = router;