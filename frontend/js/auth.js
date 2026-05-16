// frontend/js/auth.js
'use strict';

document.addEventListener('DOMContentLoaded', async () => {
    const loginForm = document.getElementById('loginForm');
    const regForm   = document.getElementById('regForm');
    const otpForm   = document.getElementById('otpForm');
    const forgotForm = document.getElementById('forgotForm');
    const resetForm  = document.getElementById('resetForm');
    const csrfToken = await Security.fetchToken();

    // ─── LOGIN FLOW ──────────────────────────────────────────
    if (loginForm) {
        loginForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                body: JSON.stringify({
                    username: loginForm.username.value,
                    password: loginForm.password.value
                })
            });

            const data = await res.json();
            if (data.success) {
                localStorage.setItem('tempUserId', data.userId);
                document.getElementById('auth-step-1').classList.add('hidden');
                document.getElementById('auth-step-otp').classList.remove('hidden');
            } else {
                Security.showThreat(data.message);
            }
        });
    }

    // ─── REGISTRATION FLOW ───────────────────────────────────
    if (regForm) {
        regForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(regForm);
            const payload = Object.fromEntries(formData.entries());

            const res = await fetch('/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                body: JSON.stringify(payload)
            });

            const data = await res.json();
            if (data.success) {
                localStorage.setItem('tempUserId', data.userId);
                document.getElementById('reg-step-1').classList.add('hidden');
                document.getElementById('reg-step-otp').classList.remove('hidden');
            } else {
                Security.showThreat(data.message);
            }
        });
    }

    // ─── OTP VERIFICATION ─────────────────────────────────────
    if (otpForm) {
        otpForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const userId = localStorage.getItem('tempUserId');
            
            let endpoint = '/api/auth/verify-login';
            if (window.location.pathname.includes('register')) endpoint = '/api/auth/verify-register';
            if (window.location.pathname.includes('forgot')) endpoint = '/api/auth/verify-forgot';

            const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                body: JSON.stringify({ userId, otp: otpForm.otp.value })
            });

            const data = await res.json();
            if (data.success) {
                if (window.location.pathname.includes('forgot')) {
                    document.getElementById('forgot-step-otp').classList.add('hidden');
                    document.getElementById('forgot-step-reset').classList.remove('hidden');
                } else {
                    localStorage.removeItem('tempUserId');
                    if (data.user && data.user.role === 'admin') {
                        window.location.href = '/admin';
                    } else {
                        window.location.href = data.token ? '/dashboard' : '/login';
                    }
                }
            } else {
                Security.showThreat(data.message);
            }
        });
    }

    // ─── FORGOT PASSWORD FLOW ─────────────────────────────────
    if (forgotForm) {
        forgotForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const res = await fetch('/api/auth/forgot-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                body: JSON.stringify({ username: forgotForm.username.value })
            });

            const data = await res.json();
            if (data.success) {
                if (data.userId) localStorage.setItem('tempUserId', data.userId);
                document.getElementById('forgot-step-1').classList.add('hidden');
                document.getElementById('forgot-step-otp').classList.remove('hidden');
            } else {
                Security.showThreat(data.message);
            }
        });
    }

    // ─── RESEND OTP FLOW ──────────────────────────────────────
    const resendBtns = document.querySelectorAll('.resendOtpBtn');
    resendBtns.forEach(btn => {
        btn.addEventListener('click', async (e) => {
            e.preventDefault();
            const userId = localStorage.getItem('tempUserId');
            if (!userId) {
                Security.showThreat('Session expired. Please start over.');
                return;
            }

            let purpose = 'login_verify';
            if (window.location.pathname.includes('register')) purpose = 'register_verify';
            if (window.location.pathname.includes('forgot')) purpose = 'forgot_password';

            try {
                const res = await fetch('/api/auth/resend-otp', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                    body: JSON.stringify({ userId, purpose })
                });

                const data = await res.json();
                if (data.success) {
                    alert('A new OTP has been sent to your email.');
                } else {
                    Security.showThreat(data.message);
                }
            } catch (err) {
                Security.showThreat('Failed to resend OTP. Please try again.');
            }
        });
    });

    // ─── RESET PASSWORD FLOW ──────────────────────────────────
    if (resetForm) {
        resetForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            const password = resetForm.password.value;
            const confirmPassword = resetForm.confirmPassword.value;

            if (password !== confirmPassword) {
                Security.showThreat('Passwords do not match');
                return;
            }

            const res = await fetch('/api/auth/reset-password', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrfToken },
                body: JSON.stringify({ password, confirmPassword })
            });

            const data = await res.json();
            if (data.success) {
                alert('Password reset successful. Please login.');
                localStorage.removeItem('tempUserId');
                window.location.href = '/login';
            } else {
                Security.showThreat(data.message);
            }
        });
    }
});