// backend/middleware/upload.js
'use strict';

const multer = require('multer');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');

// Ensure upload directory exists
const uploadDir = path.join(__dirname, '../../uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir, { recursive: true });
}

// Storage configuration
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        // Generate a random filename to prevent path traversal and execution of malicious files
        const randomName = crypto.randomBytes(16).toString('hex');
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${randomName}${ext}`);
    }
});

// File filter for security
const fileFilter = (req, file, cb) => {
    // Only allow specific mimetypes
    const allowedMimeTypes = ['application/pdf', 'image/png', 'image/jpeg', 'image/jpg'];
    if (allowedMimeTypes.includes(file.mimetype)) {
        cb(null, true);
    } else {
        cb(new Error('Invalid file type. Only PDF, PNG, and JPEG are allowed.'), false);
    }
};

// Multer upload instance
const upload = multer({
    storage: storage,
    limits: {
        fileSize: 2 * 1024 * 1024, // 2 MB limit
        files: 1 // Maximum 1 file per request
    },
    fileFilter: fileFilter
});

// Middleware wrapper to handle multer errors gracefully
const secureUpload = (field) => {
    return (req, res, next) => {
        const uploadMiddleware = upload.single(field);
        uploadMiddleware(req, res, function (err) {
            if (err instanceof multer.MulterError) {
                // A Multer error occurred when uploading.
                return res.status(400).json({ success: false, message: `Upload error: ${err.message}` });
            } else if (err) {
                // An unknown error occurred.
                return res.status(400).json({ success: false, message: err.message });
            }
            // Everything went fine.
            next();
        });
    };
};

module.exports = {
    secureUpload
};
