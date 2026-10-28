import { apiFetch } from './client';

export const listFlagged = () => apiFetch('/auditor/flagged-sessions');

export const reviewFlagged = (riskScoreId, status) =>
  apiFetch(`/auditor/flagged-sessions/${riskScoreId}/review`, {
    method: 'POST',
    body: { status },
  });

export const listAuditLog = (params = {}) => {
  const qs = new URLSearchParams(params).toString();
  return apiFetch(`/auditor/audit-log${qs ? `?${qs}` : ''}`);
};
