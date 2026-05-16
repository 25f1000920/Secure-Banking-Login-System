// frontend/js/dashboard.js
'use strict';

document.addEventListener('DOMContentLoaded', async () => {
    const loanForm = document.getElementById('loanForm');
    const logoutBtn = document.getElementById('logoutBtn');
    const csrfToken = await Security.fetchToken();

    // ─── Loan Submission ──────────────────────────────────────
    if (loanForm) {
        loanForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(loanForm);
            const res = await fetch('/api/loan/apply', {
                method: 'POST',
                headers: { 
                    'x-csrf-token': csrfToken 
                },
                body: formData
            });

            const data = await res.json();
            if (data.success) {
                alert('Loan Application Submitted Successfully!');
                loanForm.reset();
            } else {
                Security.showThreat(data.message);
            }
        });
    }

    // ─── Logout ──────────────────────────────────────────────
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await fetch('/api/auth/logout', { 
                method: 'POST', 
                headers: { 'x-csrf-token': csrfToken } 
            });
            window.location.href = '/pages/login.html';
        });
    }
});