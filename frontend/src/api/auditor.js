import { apiFetch, apiDownload } from './client';

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

// report: 'audit-log' | 'flagged-sessions' | 'consent-activity'
export const downloadReport = (report, format, filters = {}) => {
  const params = Object.fromEntries(Object.entries({ ...filters, format }).filter(([, v]) => v));
  return apiDownload(`/auditor/reports/${report}?${new URLSearchParams(params)}`);
};
