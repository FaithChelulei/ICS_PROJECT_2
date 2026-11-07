import { apiFetch, apiDownload } from './client';

export const getAuditorOverview = () => apiFetch('/auditor/overview');

// Every status: the page filters them itself, and the server's default is
// pending only, which would leave the other tabs and breach decisions empty.
export const listFlagged = () => apiFetch('/auditor/flagged-sessions?status=all');

export const getRiskThresholds = () => apiFetch('/auditor/risk-thresholds');

// Needs the auditor's password again (step-up check).
export const updateRiskThreshold = (role, threshold, reason, password) =>
  apiFetch(`/auditor/risk-thresholds/${role}`, { method: 'POST', body: { threshold, reason, password } });

export const reviewFlagged = (riskScoreId, status) =>
  apiFetch(`/auditor/flagged-sessions/${riskScoreId}/review`, {
    method: 'POST',
    body: { status },
  });

// decision: 'notified_commissioner' | 'no_real_risk' (KDPA s.43)
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
