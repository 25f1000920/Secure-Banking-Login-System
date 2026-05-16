// backend/routes/admin.routes.js
'use strict';

const express = require('express');
const router  = express.Router();
const db      = require('../config/db');
const { requireRole } = require('../middleware/auth');
const { body, validationResult } = require('express-validator');
const { decrypt } = require('../utils/crypto');

// Require admin role for all routes in this file
router.use(requireRole('admin'));

router.get('/loans', async (req, res) => {
    try {
        const { rows } = await db.query(
            'SELECT id, applicant_name, loan_amount, loan_purpose, institution_name, course_name, course_duration, annual_income, collateral, collateral_file, status, submitted_at FROM loan_applications ORDER BY submitted_at DESC'
        );
        
        // Decrypt sensitive data before sending to admin
        const decryptedRows = rows.map(row => {
            return {
                ...row,
                annual_income: decrypt(row.annual_income)
            };
        });
        
        res.json({ success: true, applications: decryptedRows });
    } catch (err) {
        console.error('[ADMIN LOANS]', err);
        res.status(500).json({ success: false, message: 'Failed to fetch loan applications.' });
    }
});

router.post('/loans/:id/status', 
    [
        body('status').isIn(['approved', 'rejected', 'pending']).withMessage('Invalid status')
    ],
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(422).json({ success: false, message: errors.array()[0].msg });
        }

        try {
            const loanId = req.params.id;
            const { status } = req.body;
            
            await db.query(
                'UPDATE loan_applications SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
                [status, loanId]
            );
            
            res.json({ success: true, message: `Loan status updated to ${status}.` });
        } catch (err) {
            console.error('[ADMIN UPDATE STATUS]', err);
            res.status(500).json({ success: false, message: 'Failed to update loan status.' });
        }
    }
);

module.exports = router;
