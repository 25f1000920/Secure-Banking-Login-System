// backend/utils/crypto.js
'use strict';

const crypto = require('crypto');
require('dotenv').config();

// Ensure ENCRYPTION_KEY is a 32-byte hexadecimal string
const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;

let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

if (!ENCRYPTION_KEY || ENCRYPTION_KEY.length !== 64) {
    // Generate a default one for development if missing
    console.warn('[SECURITY WARNING] ENCRYPTION_KEY is missing or invalid in .env! Using a random key for this session. Data encrypted now will be lost on restart.');
    ENCRYPTION_KEY = crypto.randomBytes(32).toString('hex');
}

const keyBuffer = Buffer.from(ENCRYPTION_KEY, 'hex');

function encrypt(text) {
    if (text === null || text === undefined) return text;
    text = String(text);
    
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, keyBuffer, iv);
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag().toString('hex');
    
    // Format: iv:authTag:encryptedText
    return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decrypt(text) {
    if (!text || typeof text !== 'string' || !text.includes(':')) return text;
    
    try {
        const parts = text.split(':');
        if (parts.length !== 3) return text;
        
        const [ivHex, authTagHex, encryptedHex] = parts;
        
        const iv = Buffer.from(ivHex, 'hex');
        const authTag = Buffer.from(authTagHex, 'hex');
        
        const decipher = crypto.createDecipheriv(ALGORITHM, keyBuffer, iv);
        decipher.setAuthTag(authTag);
        
        let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        
        return decrypted;
    } catch (error) {
        console.error('[CRYPTO ERROR] Decryption failed:', error.message);
        return '*** DECRYPTION_FAILED ***';
    }
}

module.exports = {
    encrypt,
    decrypt
};
