import { apiFetch } from './client';

export const listRegistrationRequests = () => apiFetch('/admin/registration-requests');

// An educator needs verificationNote: how the admin confirmed it with the ECD centre.
export const approveRequest = (id, verificationNote) =>
  apiFetch(`/admin/registration-requests/${id}/approve`, { method: 'POST', body: verificationNote ? { verificationNote } : {} });

export const rejectRequest = (id, rejectionReason) =>
  apiFetch(`/admin/registration-requests/${id}/reject`, {
    method: 'POST',
    body: { rejectionReason },
  });

export const listUsers = () => apiFetch('/admin/users');

export const listLockedUsers = () => apiFetch('/admin/users/locked');

export const unlockAccount = (id) =>
  apiFetch(`/admin/users/${id}/unlock`, { method: 'POST' });

export const getEncryptionStatus = () => apiFetch('/admin/encryption/status');

// Both need the admin's password again (step-up check).
// Needs an approval from a second System Administrator (see Approvals).
export const reencryptData = (password, approvalId) =>
  apiFetch('/admin/encryption/reencrypt', { method: 'POST', body: { password, approvalId } });

export const getRetentionStatus = () => apiFetch('/admin/retention/status');
export const applyRetention = (password, approvalId) =>
  apiFetch('/admin/retention/apply', { method: 'POST', body: { password, approvalId } });

export const getAdminOverview = () => apiFetch('/admin/overview');

// Both need the admin's password again (step-up check).
export const changeUserRole = (id, role, reason, password) =>
  apiFetch(`/admin/users/${id}/role`, { method: 'POST', body: { role, reason, password } });

export const getSettings = () => apiFetch('/admin/settings');
export const updateSetting = (key, value, reason, password) =>
  apiFetch(`/admin/settings/${key}`, { method: 'POST', body: { value, reason, password } });

// Two-person approval. action: 'reencrypt_data' | 'apply_retention'
export const listApprovals = () => apiFetch('/admin/approvals');
export const requestApproval = (action, reason, password) =>
  apiFetch('/admin/approvals', { method: 'POST', body: { action, reason, password } });
export const approveApproval = (id, reason, password) =>
  apiFetch(`/admin/approvals/${id}/approve`, { method: 'POST', body: { reason, password } });
export const rejectApproval = (id, reason, password) =>
  apiFetch(`/admin/approvals/${id}/reject`, { method: 'POST', body: { reason, password } });

// Layer 2 for System Administrators: the Security Auditors' weeks.
export const getAuditorWeeks = (week) => apiFetch(`/admin/weekly-review${week ? `?week=${week}` : ''}`);
export const getAuditorWeekDetail = (id) => apiFetch(`/admin/weekly-review/${id}`);
export const decideAuditorWeek = (id, status, note) =>
  apiFetch(`/admin/weekly-review/${id}/decision`, { method: 'POST', body: { status, note } });

// DPIA G1: clear device names, network addresses and model evidence older
// than the monitoring period now (it also runs every night).
export const clearMonitoringData = (password) =>
  apiFetch('/admin/retention/monitoring/clear', { method: 'POST', body: { password } });

// "Take action" cases from the weekly review. Pause and decide need the
// admin's password again (step-up check).
export const listCases = () => apiFetch('/admin/cases');
export const pauseCase = (id, note, password) =>
  apiFetch(`/admin/cases/${id}/pause`, { method: 'POST', body: { note, password } });
export const decideCase = (id, decision, note, password) =>
  apiFetch(`/admin/cases/${id}/decision`, { method: 'POST', body: { decision, note, password } });
