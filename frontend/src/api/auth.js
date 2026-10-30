import { apiFetch } from './client';

export const login = (identifier, password) =>
  apiFetch('/auth/login', { method: 'POST', body: { identifier, password }, auth: false });

export const verifyMfa = (userId, code) =>
  apiFetch('/auth/verify-mfa', { method: 'POST', body: { userId, code }, auth: false });

export const logout = () => apiFetch('/auth/logout', { method: 'POST' });

export const me = () => apiFetch('/auth/me');

export const changePassword = (currentPassword, newPassword) =>
  apiFetch('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } });

export const registerRequest = (payload) =>
  apiFetch('/auth/register', { method: 'POST', body: payload, auth: false });
