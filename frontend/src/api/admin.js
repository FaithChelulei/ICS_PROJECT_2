import { apiFetch } from './client';

export const listRegistrationRequests = () => apiFetch('/admin/registration-requests');

export const approveRequest = (id) =>
  apiFetch(`/admin/registration-requests/${id}/approve`, { method: 'POST' });

export const rejectRequest = (id, rejectionReason) =>
  apiFetch(`/admin/registration-requests/${id}/reject`, {
    method: 'POST',
    body: { rejectionReason },
  });

export const listLockedUsers = () => apiFetch('/admin/users/locked');

export const unlockAccount = (id) =>
  apiFetch(`/admin/users/${id}/unlock`, { method: 'POST' });

export const getEncryptionStatus = () => apiFetch('/admin/encryption/status');

export const reencryptData = () => apiFetch('/admin/encryption/reencrypt', { method: 'POST' });

export const getRetentionStatus = () => apiFetch('/admin/retention/status');
export const applyRetention = () => apiFetch('/admin/retention/apply', { method: 'POST' });
