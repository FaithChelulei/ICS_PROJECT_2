import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { listFlagged, reviewFlagged } from '../../api/auditor';
import { PageHeader, Card, Alert, EmptyState, Spinner, Badge } from '../../components/ui.jsx';

const NAV = [
  { to: '/', label: 'Flagged Sessions' },
  { to: '/auditor/audit-log', label: 'Audit Log' },
];
const FILTERS = ['pending', 'reviewing', 'confirmed', 'escalated', 'all'];
const STATUS_COLOR = { pending: 'amber', reviewing: 'brand', confirmed: 'green', escalated: 'red' };

export default function AuditorDashboard() {
  const [sessions, setSessions] = useState([]);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const data = await listFlagged();
      setSessions(data.flaggedSessions);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleReview(riskScoreId, status) {
    setBusyId(riskScoreId);
    try {
      await reviewFlagged(riskScoreId, status);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  const visible = sessions.filter((s) =>
    statusFilter === 'all' ? true : s.auditor_status === statusFilter
  );
  const avgScore = sessions.length
    ? (sessions.reduce((sum, s) => sum + Number(s.combined_score), 0) / sessions.length).toFixed(2)
    : '—';

  return (
    <Layout navItems={NAV} portalLabel="Security Auditor" theme="dark">
      <PageHeader title="Flagged Sessions" subtitle="Sessions marked for review" />

      <div className="p-8">
        {error && <Alert className="mb-6">{error}</Alert>}

        <div className="grid grid-cols-3 gap-4 mb-6">
          {[
            { label: 'Flagged (this filter)', value: visible.length, tone: 'text-red-600' },
            { label: 'Avg. Risk Score (all flagged)', value: avgScore, tone: 'text-ink' },
            { label: 'Total Flagged', value: sessions.length, tone: 'text-ink' },
          ].map((s) => (
            <Card key={s.label} className="p-5">
              <div className="text-sm text-slate-500 mb-1">{s.label}</div>
              <div className={`text-3xl font-extrabold ${s.tone}`}>{s.value}</div>
            </Card>
          ))}
        </div>

        <div className="flex gap-2 mb-5">
          {FILTERS.map((s) => (
            <button
              key={s}
              onClick={() => setStatusFilter(s)}
              className={`px-3.5 py-1.5 text-sm font-medium rounded-full border transition capitalize ${
                statusFilter === s
                  ? 'bg-brand-600 text-white border-brand-600'
                  : 'bg-white text-slate-600 border-[#EFE4D0] hover:border-brand-300'
              }`}
            >
              {s}
            </button>
          ))}
        </div>

        {loading ? (
          <Spinner />
        ) : visible.length === 0 ? (
          <EmptyState>No sessions in this filter.</EmptyState>
        ) : (
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <div className="min-w-[880px]">
                <div className="grid grid-cols-[120px_1fr_150px_90px_110px_150px] bg-cream-100 border-b border-[#EFE4D0] px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide gap-3">
                  <span>Time</span>
                  <span>User / Role</span>
                  <span>Action</span>
                  <span>Risk</span>
                  <span>Status</span>
                  <span>Set Status</span>
                </div>

                {visible.map((s) => (
                  <div
                    key={s.risk_score_id}
                    className="grid grid-cols-[120px_1fr_150px_90px_110px_150px] px-5 py-4 text-sm items-center gap-3 border-b border-[#F1E7D3] last:border-0"
                  >
                    <span className="text-slate-400 text-xs font-mono truncate">
                      {new Date(s.created_at).toLocaleString()}
                    </span>
                    <span className="min-w-0 text-ink font-medium truncate" title={`${s.email} (${s.role})`}>
                      {s.email} <span className="text-slate-400 font-normal">({s.role})</span>
                    </span>
                    <span className="min-w-0 text-slate-500 truncate" title={s.action_type}>
                      {s.action_type}
                    </span>
                    <span
                      className={`font-mono font-semibold ${
                        Number(s.combined_score) > 0.7 ? 'text-red-600' : 'text-amber-600'
                      }`}
                    >
                      {Number(s.combined_score).toFixed(3)}
                    </span>
                    <Badge color={STATUS_COLOR[s.auditor_status] || 'gray'}>{s.auditor_status}</Badge>
                    <select
                      value={s.auditor_status}
                      disabled={busyId === s.risk_score_id}
                      onChange={(e) => handleReview(s.risk_score_id, e.target.value)}
                      className="w-full rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-sm font-medium text-ink shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-100 capitalize"
                    >
                      {['pending', 'reviewing', 'confirmed', 'escalated'].map((opt) => (
                        <option key={opt} value={opt} className="capitalize">
                          {opt}
                        </option>
                      ))}
                    </select>
                  </div>
                ))}
              </div>
            </div>
          </Card>
        )}
      </div>
    </Layout>
  );
}
