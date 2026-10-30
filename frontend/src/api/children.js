import { apiFetch } from './client';

export const listMyChildren = () => apiFetch('/children');

export const createChildProfile = (payload) =>
  apiFetch('/children', { method: 'POST', body: payload });

// Only the fields present in `changes` are corrected.
export const updateChildDetails = (childProfileId, changes) =>
  apiFetch(`/children/${childProfileId}`, { method: 'PATCH', body: changes });

// Restrict (KDPA s.40(3)) / lift the restriction.
export const archiveChild = (childProfileId, reason) =>
  apiFetch(`/children/${childProfileId}/archive`, { method: 'POST', body: { reason } });

export const restoreChild = (childProfileId) =>
  apiFetch(`/children/${childProfileId}/restore`, { method: 'POST' });

export const listRecords = (childProfileId) =>
  apiFetch(`/children/${childProfileId}/records`);

export const submitRecord = (childProfileId, payload) =>
  apiFetch(`/children/${childProfileId}/records`, { method: 'POST', body: payload });

export const getConsent = (childProfileId) =>
  apiFetch(`/children/${childProfileId}/consent`);

export const setConsent = (childProfileId, scope, consentGiven) =>
  apiFetch(`/children/${childProfileId}/consent`, {
    method: 'POST',
    body: { scope, consentGiven },
  });
