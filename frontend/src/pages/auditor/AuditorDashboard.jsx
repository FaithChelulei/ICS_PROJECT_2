import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { listFlagged, reviewFlagged, recordBreachDecision, getAuditorOverview } from '../../api/auditor';
import { PageHeader, Card, Alert, EmptyState, Spinner, Badge, Button, StatCard } from '../../components/ui.jsx';
import { AUDITOR_NAV as NAV } from './nav.js';
const FILTERS = ['pending', 'reviewing', 'confirmed', 'escalated', 'all'];
const STATUS_COLOR = { pending: 'amber', reviewing: 'brand', confirmed: 'green', escalated: 'red' };

// KDPA s.43: a suspected breach -- a session the auditor escalated, or one
// whose owner answered "This was NOT me" -- needs a recorded decision within
// 72 hours of detection: Data Commissioner notified, or no real risk of harm.
const BREACH_WINDOW_HOURS = 72;
const isBreachCandidate = (s) => s.auditor_status === 'escalated' || s.owner_response === 'not_me';
const hoursSince = (iso, to = Date.now()) => (new Date(to) - new Date(iso)) / 3600000;

// Summary row, 14-day chart and likely reasons, above the review list.
function OverviewPanels({ overview: o }) {
  const change = o.flagsThisWeek - o.flagsLastWeek;
  const weekHint = change === 0 ? 'Same as last week' : `${Math.abs(change)} ${change > 0 ? 'more' : 'fewer'} than last week`;
  const breachHint = o.breachOverdue
    ? `${o.breachOverdue} overdue`
    : o.breachHoursLeft === null ? 'None open' : `${o.breachHoursLeft} hours left`;
  const highest = Math.max(...o.flagsPerDay.map((d) => d.flags));

  return (
    <div className="mb-6 space-y-4">
      <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard label="Flags this week" value={o.flagsThisWeek} icon="flag" iconTone="coral" hint={weekHint} />
        <StatCard
          label="Waiting for review"
          value={o.waitingForReview}
          icon="clock"
          iconTone="amber"
          hint={o.oldestWaiting ? `Oldest ${Math.floor(hoursSince(o.oldestWaiting))} h ago` : 'Nothing waiting'}
        />
        <StatCard
          label="Breach decisions open"
          value={o.breachOpen}
          tone={o.breachOverdue ? 'text-red-600' : 'text-ink'}
          icon="shield"
          iconTone="red"
          hint={breachHint}
        />
        <StatCard label="Reviewed" value={o.reviewedThisMonth} icon="check" hint="Flagged this month" />
      </div>
      <div className="grid xl:grid-cols-[3fr_2fr] gap-4 items-start">
        <Card className="p-5">
          <h2 className="text-[15px] font-semibold text-ink mb-3">Flags per day, last 14 days</h2>
          <div className="flex h-24 items-end gap-1.5 border-b border-[#EFE4D0]">
            {o.flagsPerDay.map((d) => (
              <div
                key={d.day}
                title={`${new Date(d.day).toLocaleDateString()}: ${d.flags} flag${d.flags === 1 ? '' : 's'}`}
                className={`flex-1 rounded-t ${highest > 0 && d.flags === highest ? 'bg-coral-500' : 'bg-brand-400'}`}
                style={{ height: highest ? `${(d.flags / highest) * 100}%` : 0 }}
              />
            ))}
          </div>
          <div className="mt-1.5 flex justify-between text-xs text-slate-400">
            <span>14 days ago</span>
            <span>Highest: {highest}</span>
            <span>Today</span>
          </div>
        </Card>
        <Card className="p-5">
          <h2 className="text-[15px] font-semibold text-ink mb-3">Likely reasons, last 7 days</h2>
          {o.reasons.length === 0 ? (
            <p className="text-sm text-slate-400">No flags in the last 7 days.</p>
          ) : (
            <ul className="space-y-2">
              {o.reasons.map((r) => (
                <li key={r.reason} className="flex justify-between gap-4 text-sm text-slate-600">
                  <span>{r.reason}</span>
                  <span className="font-mono text-slate-400">{r.count}</span>
                </li>
              ))}
            </ul>
          )}
          <p className="mt-3 text-xs text-slate-400">The model gives a score, not a reason. These are worked out from each flagged action.</p>
        </Card>
      </div>
    </div>
  );
}

const DECISION_LABEL = {
  notified_commissioner: 'Data Commissioner notified',
  no_real_risk: 'Assessed: no real risk of harm',
};

function BreachPanel({ session: s, onRecorded, onError }) {
  const [decision, setDecision] = useState('no_real_risk');
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const why = s.owner_response === 'not_me' ? 'Owner reported “This was NOT me”' : 'Escalated by an auditor';

  if (s.breach_decision) {
    const took = hoursSince(s.created_at, s.breach_decided_at);
    return (
      <div className="px-5 pb-4 -mt-1 text-sm text-slate-500 flex flex-wrap items-center gap-2">
        <Badge color={took <= BREACH_WINDOW_HOURS ? 'green' : 'amber'}>Breach decision</Badge>
        <span className="text-ink font-medium">{DECISION_LABEL[s.breach_decision]}</span>
        <span>· {took.toFixed(0)} h after detection</span>
        <span className="truncate max-w-[40ch]" title={s.breach_decision_reason}>· {s.breach_decision_reason}</span>
      </div>
    );
  }

  const elapsed = hoursSince(s.created_at);
  const overdue = elapsed > BREACH_WINDOW_HOURS;

  async function handleSubmit(e) {
    e.preventDefault();
    setBusy(true);
    try {
      await recordBreachDecision(s.risk_score_id, decision, reason);
      await onRecorded();
    } catch (err) {
      onError(err.message);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="px-5 pb-4 -mt-1 flex flex-wrap items-center gap-2 text-sm">
      <Badge color={overdue ? 'red' : 'amber'}>
        {overdue ? `Overdue: ${elapsed.toFixed(0)} h` : `${elapsed.toFixed(0)} h of 72`}
      </Badge>
      <span className="text-slate-500">{why}. Record the breach decision:</span>
      <select
        value={decision}
        onChange={(e) => setDecision(e.target.value)}
        className="rounded-lg border border-slate-300 bg-white px-2 py-1.5 text-sm text-ink"
      >
        <option value="no_real_risk">No real risk of harm</option>
        <option value="notified_commissioner">Data Commissioner notified</option>
      </select>
      <input
        required
        minLength={10}
        value={reason}
        onChange={(e) => setReason(e.target.value)}
        placeholder="Reasoning (kept as evidence)"
        className="flex-1 min-w-[16rem] rounded-lg border border-slate-300 bg-white px-2.5 py-1.5 text-sm text-ink"
      />
      <Button size="sm" disabled={busy}>{busy ? 'Saving…' : 'Record'}</Button>
    </form>
  );
}

export default function AuditorDashboard() {
  const [sessions, setSessions] = useState([]);
  const [statusFilter, setStatusFilter] = useState('pending');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [busyId, setBusyId] = useState(null);
  const [overview, setOverview] = useState(null);

  async function load() {
    setLoading(true);
    setError('');
    // The summary is extra: if it fails, the review list below still works.
    getAuditorOverview().then(setOverview).catch(() => setOverview(null));
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

  return (
    <Layout navItems={NAV} portalLabel="Security Auditor" theme="dark">
      <PageHeader
        title="Flagged Sessions"
        subtitle={overview ? `${overview.waitingForReview} session${overview.waitingForReview === 1 ? '' : 's'} waiting for your review` : 'Sessions marked for review'}
        actions={
          <Link to="/auditor/reports">
            <Button>Download report</Button>
          </Link>
        }
      />

      <div className="px-8 py-6">
        {error && <Alert className="mb-6">{error}</Alert>}

        {overview && <OverviewPanels overview={overview} />}

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
                  <span>What happened</span>
                  <span>Risk</span>
                  <span>Status</span>
                  <span>Set Status</span>
                </div>

                {visible.map((s) => (
                  <div key={s.risk_score_id} className="border-b border-[#F1E7D3] last:border-0">
                  <div className="grid grid-cols-[120px_1fr_150px_90px_110px_150px] px-5 py-4 text-sm items-center gap-3">
                    <span className="text-slate-400 text-xs font-mono truncate">
                      {new Date(s.created_at).toLocaleString()}
                    </span>
                    <span className="min-w-0 text-ink font-medium truncate" title={`${s.email} (${s.role})`}>
                      {s.email} <span className="text-slate-400 font-normal">({s.role})</span>
                    </span>
                    <span className="min-w-0" title={`Likely reason: ${s.likely_reason}. Action: ${s.action_type}`}>
                      <span className="block truncate text-ink">{s.likely_reason}</span>
                      <span className="block truncate text-xs text-slate-400">{s.action_type}</span>
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
                  {isBreachCandidate(s) && <BreachPanel session={s} onRecorded={load} onError={setError} />}
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
