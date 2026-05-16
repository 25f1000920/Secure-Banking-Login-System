// frontend/js/security.js
'use strict';

const Security = {
    // Automatically fetches and handles CSRF tokens for all state-changing requests
    async fetchToken() {
        try {
            const response = await fetch('/api/auth/csrf-token');
            const data = await response.json();
            return data.csrfToken;
        } catch (err) {
            console.error('[SECURITY] Failed to retrieve CSRF token.');
            return null;
        }
    },

    // Displays the Active Defense warning if an attack is detected
    showThreat(message) {
        const banner = document.getElementById('securityBanner');
        if (banner) {
            banner.textContent = message;
            banner.style.display = 'block';
            setTimeout(() => { banner.style.display = 'none'; }, 8000);
        }
    },

    // Escapes HTML characters to prevent DOM-based XSS when rendering user input
    escapeHTML(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }
};