import { apiFetch } from './client';

export const listRegistrationRequests = () => apiFetch('/admin/registration-requests');

export const approveRequest = (id) =>
  apiFetch(`/admin/registration-requests/${id}/approve`, { method: 'POST' });

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
export const reencryptData = (password) =>
  apiFetch('/admin/encryption/reencrypt', { method: 'POST', body: { password } });

export const getRetentionStatus = () => apiFetch('/admin/retention/status');
export const applyRetention = (password) =>
  apiFetch('/admin/retention/apply', { method: 'POST', body: { password } });

export const getAdminOverview = () => apiFetch('/admin/overview');

// Both need the admin's password again (step-up check).
export const changeUserRole = (id, role, reason, password) =>
  apiFetch(`/admin/users/${id}/role`, { method: 'POST', body: { role, reason, password } });

export const getSettings = () => apiFetch('/admin/settings');
export const updateSetting = (key, value, reason, password) =>
  apiFetch(`/admin/settings/${key}`, { method: 'POST', body: { value, reason, password } });
