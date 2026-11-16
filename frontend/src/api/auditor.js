import { apiFetch, apiDownload } from './client';

export const getAuditorOverview = () => apiFetch('/auditor/overview');

// Every status: the page filters them itself, and the server's default is
// pending only, which would leave the other tabs and breach decisions empty.
export const listFlagged = () => apiFetch('/auditor/flagged-sessions?status=all');


export const reviewFlagged = (riskScoreId, status) =>
  apiFetch(`/auditor/flagged-sessions/${riskScoreId}/review`, {
    method: 'POST',
    body: { status },
  });

// decision: 'reported_to_admin' | 'no_real_risk' (KDPA s.43)
export const recordBreachDecision = (riskScoreId, decision, reason) =>
  apiFetch(`/auditor/flagged-sessions/${riskScoreId}/breach-decision`, {
    method: 'POST',
    body: { decision, reason },
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

// Layer 2: "People to review this week". week = any date in the week (YYYY-MM-DD).
export const getWeeklyReview = (week, role) => {
  const qs = new URLSearchParams(Object.fromEntries(Object.entries({ week, role }).filter(([, v]) => v)));
  return apiFetch(`/auditor/weekly-review${qs.toString() ? `?${qs}` : ''}`);
};
export const getWeeklyDetail = (id) => apiFetch(`/auditor/weekly-review/${id}`);
// status: 'no_concern' | 'escalated'; note: at least 10 characters
export const decideWeekly = (id, status, note) =>
  apiFetch(`/auditor/weekly-review/${id}/decision`, { method: 'POST', body: { status, note } });
export const refreshWeekly = () => apiFetch('/auditor/weekly-review/refresh', { method: 'POST' });
