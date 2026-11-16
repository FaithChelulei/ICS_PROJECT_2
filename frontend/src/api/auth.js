import { apiFetch } from './client';

export const login = (identifier, password) =>
  apiFetch('/auth/login', { method: 'POST', body: { identifier, password }, auth: false });

export const verifyMfa = (challengeId, code) =>
  apiFetch('/auth/verify-mfa', { method: 'POST', body: { challengeId, code }, auth: false });

export const logout = () => apiFetch('/auth/logout', { method: 'POST' });

export const me = () => apiFetch('/auth/me');

// A paused account (until verified): see the pause and send an explanation.
export const getPausedCase = () => apiFetch('/auth/paused-case');
export const sendExplanation = (explanation) =>
  apiFetch('/auth/paused-case/explanation', { method: 'POST', body: { explanation } });

export const changePassword = (currentPassword, newPassword) =>
  apiFetch('/auth/change-password', { method: 'POST', body: { currentPassword, newPassword } });

export const registerRequest = (payload) =>
  apiFetch('/auth/register', { method: 'POST', body: payload, auth: false });
