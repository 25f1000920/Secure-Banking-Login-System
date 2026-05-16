// frontend/js/admin.js
'use strict';

document.addEventListener('DOMContentLoaded', async () => {
    const logoutBtn = document.getElementById('logoutBtn');
    const loansTableBody = document.getElementById('loansTableBody');
    const csrfToken = await Security.fetchToken();

    // ─── Fetch All Loans ───────────────────────────────────────
    async function fetchLoans() {
        try {
            const res = await fetch('/api/admin/loans', {
                headers: { 'x-csrf-token': csrfToken }
            });

            if (res.status === 403) {
                alert('Access Denied. You do not have admin privileges.');
                window.location.href = '/dashboard';
                return;
            }

            const data = await res.json();
            if (data.success) {
                renderLoans(data.applications);
            } else {
                Security.showThreat(data.message);
            }
        } catch (err) {
            console.error('Failed to fetch loans', err);
        }
    }

    function renderLoans(loans) {
        loansTableBody.innerHTML = '';
        loans.forEach(loan => {
            const tr = document.createElement('tr');
            tr.style.borderBottom = '1px solid rgba(255, 255, 255, 0.1)';
            
            const date = new Date(loan.submitted_at).toLocaleDateString();
            
            tr.innerHTML = `
                <td style="padding: 10px;">${loan.id}</td>
                <td style="padding: 10px;">${Security.escapeHTML(loan.applicant_name)}</td>
                <td style="padding: 10px;">$${loan.loan_amount}</td>
                <td style="padding: 10px;">$${Security.escapeHTML(loan.annual_income)}</td>
                <td style="padding: 10px;">${date}</td>
                <td style="padding: 10px;">
                    <span style="color: ${loan.status === 'approved' ? '#10b981' : loan.status === 'rejected' ? '#ef4444' : '#f59e0b'}; font-weight: bold;">
                        ${loan.status.toUpperCase()}
                    </span>
                </td>
                <td style="padding: 10px;">
                    <select class="status-select" data-id="${loan.id}" style="padding: 5px; background: rgba(255,255,255,0.1); color: white; border: 1px solid rgba(255,255,255,0.2); border-radius: 4px;">
                        <option value="pending" ${loan.status === 'pending' ? 'selected' : ''} style="color: black;">Pending</option>
                        <option value="approved" ${loan.status === 'approved' ? 'selected' : ''} style="color: black;">Approve</option>
                        <option value="rejected" ${loan.status === 'rejected' ? 'selected' : ''} style="color: black;">Reject</option>
                    </select>
                </td>
            `;
            loansTableBody.appendChild(tr);
        });

        // Add event listeners to dropdowns
        document.querySelectorAll('.status-select').forEach(select => {
            select.addEventListener('change', async (e) => {
                const loanId = e.target.getAttribute('data-id');
                const newStatus = e.target.value;
                await updateStatus(loanId, newStatus);
            });
        });
    }

    async function updateStatus(loanId, status) {
        try {
            const res = await fetch(`/api/admin/loans/${loanId}/status`, {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'x-csrf-token': csrfToken 
                },
                body: JSON.stringify({ status })
            });

            const data = await res.json();
            if (data.success) {
                alert('Status updated successfully');
                fetchLoans(); // Refresh
            } else {
                alert('Error updating status: ' + data.message);
                fetchLoans(); // Revert
            }
        } catch (err) {
            console.error('Update failed', err);
        }
    }

    // ─── Logout ──────────────────────────────────────────────
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async () => {
            await fetch('/api/auth/logout', { 
                method: 'POST', 
                headers: { 'x-csrf-token': csrfToken } 
            });
            window.location.href = '/login';
        });
    }

    fetchLoans();
});
