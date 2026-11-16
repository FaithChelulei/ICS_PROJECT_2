import { apiFetch } from './client';

// My requests, and the children whose parent has granted me access.
export const listSharedChildren = () => apiFetch('/educator/children');

// Ask for access to a child by their full name and a reason; the request goes to the child's parent.
export const requestChildAccess = (childName, reason) =>
  apiFetch('/educator/access-requests', { method: 'POST', body: { childName, reason } });

// Read-only: one shared child's name, age and developmental records.
export const viewSharedRecords = (childProfileId) => apiFetch(`/educator/children/${childProfileId}/records`);
