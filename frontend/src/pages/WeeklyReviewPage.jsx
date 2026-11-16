import { useCallback, useEffect, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../components/Layout.jsx';
import { PageHeader, Card, Alert, Badge, Button, Spinner, StatCard, EmptyState, Field, inputClass } from '../components/ui.jsx';
import { getWeeklyReview, getWeeklyDetail, decideWeekly, refreshWeekly } from '../api/auditor';
import { getAuditorWeeks, getAuditorWeekDetail, decideAuditorWeek } from '../api/admin';
import { AUDITOR_NAV } from './auditor/nav.js';
import { ADMIN_NAV } from './admin/nav.js';

const ROLE_LABEL = { Caregiver: 'Caregiver', Educator: 'Educator', SecurityAuditor: 'Security Auditor', SysAdmin: 'System Admin' };
const STATUS = {
  not_reviewed: { label: 'Not reviewed', color: 'amber' },
  no_concern: { label: 'No concern', color: 'green' },
  escalated: { label: 'Action needed', color: 'red' },
};
// The case "Take action" opens (db/013), as the auditor sees it.
const CASE = {
  reported: { label: 'With the admin', color: 'amber' },
  paused: { label: 'Paused until verified', color: 'red' },
  explained: { label: 'Explanation received', color: 'amber' },
  verified: { label: 'Resolved: verified', color: 'green' },
  removed: { label: 'Resolved: access removed', color: 'gray' },
};
// The personal comparison needs 7 days of the person's own history.
const BASELINE_DAYS = 7;

// "2026-11-09/2026-11-15" -> "9 to 15 November 2026" (or "30 November to 6 December 2026").
function weekText(label, short = false) {
  const [a, b] = String(label || '').split('/').map((d) => new Date(`${d}T12:00:00`));
  if (!a || !b || Number.isNaN(a.getTime()) || Number.isNaN(b.getTime())) return label;
  const month = (d) => d.toLocaleDateString(undefined, { month: short ? 'short' : 'long' });
  const from = a.getMonth() === b.getMonth() ? `${a.getDate()}` : `${a.getDate()} ${month(a)}`;
  return `${from} to ${b.getDate()} ${month(b)}${short ? '' : ` ${b.getFullYear()}`}`;
}

// One score, in plain words: above or below its line, and whether it is the
// reason the person is listed. The numbers stay one click away.
function Verdict({ label, above, isReason }) {
  return (
    <div className="flex flex-wrap items-center gap-2 py-1.5">
      <span className={`h-2.5 w-2.5 rounded-full ${above ? 'bg-red-500' : 'bg-emerald-500'}`} />
      <span className="text-ink">{label}:</span>
      <strong className={above ? 'text-red-700' : 'text-emerald-700'}>{above ? 'above the line' : 'below the line'}</strong>
      {isReason && <span className="text-slate-600">(this is why they are listed)</span>}
    </div>
  );
}

// Monday of the week containing `d`, as YYYY-MM-DD (local time).
function mondayOf(d) {
  const x = new Date(d);
  x.setHours(12, 0, 0, 0);
  x.setDate(x.getDate() - ((x.getDay() + 6) % 7));
  return `${x.getFullYear()}-${String(x.getMonth() + 1).padStart(2, '0')}-${String(x.getDate()).padStart(2, '0')}`;
}
const shiftWeek = (monday, weeks) => mondayOf(new Date(new Date(`${monday}T12:00:00`).getTime() + weeks * 7 * 864e5));
const weekLabel = (monday) => {
  const a = new Date(`${monday}T12:00:00`);
  const b = new Date(a.getTime() + 6 * 864e5);
  const f = (d) => d.toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
  return `${f(a)} – ${f(b)} ${b.getFullYear()}`;
};

// Layer 2: "People to review this week". The model ranks; a person decides.
// scope 'auditor': every role's weeks except your own. scope 'admin': the
// Security Auditors' weeks, so the auditors are reviewed too.
export default function WeeklyReviewPage({ scope = 'auditor' }) {
  const isAdmin = scope === 'admin';
  const api = isAdmin
    ? { list: (week) => getAuditorWeeks(week), detail: getAuditorWeekDetail, decide: decideAuditorWeek }
    : { list: (week, role) => getWeeklyReview(week, role), detail: getWeeklyDetail, decide: decideWeekly };

  const [week, setWeek] = useState(mondayOf(new Date()));
  const [role, setRole] = useState('');
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [open, setOpen] = useState(null); // { review, days }
  const [showNumbers, setShowNumbers] = useState(false);
  const [decision, setDecision] = useState({ status: '', note: '' });
  const [busy, setBusy] = useState(false);
  const detailRef = useRef(null);

  // Bring the opened week into view (the list can be long).
  useEffect(() => {
    if (open && detailRef.current) detailRef.current.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [open]);

  const load = useCallback(async () => {
    setError('');
    try {
      setData(await api.list(week, role || undefined));
    } catch (err) {
      setError(err.message);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [week, role, scope]);

  useEffect(() => {
    setData(null);
    load();
  }, [load]);

  async function openRow(id) {
    setMessage('');
    setDecision({ status: '', note: '' });
    try {
      setShowNumbers(false);
      setOpen(await api.detail(id));
    } catch (err) {
      setError(err.message);
    }
  }

  async function submitDecision(e) {
    e.preventDefault();
    setBusy(true);
    try {
      const res = await api.decide(open.review.id, decision.status, decision.note);
      setMessage(res.riskNotice || (res.adminsTold
        ? 'Recorded: action needed. The System Administrators have been emailed to follow it up.'
        : `Recorded: ${STATUS[decision.status].label.toLowerCase()}.`));
      setOpen(null);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function refresh() {
    setBusy(true);
    setMessage('');
    try {
      await refreshWeekly();
      setMessage('The week has been re-scored.');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const thisWeek = mondayOf(new Date());
  const last = data && data.lastRefresh;

  return (
    <Layout navItems={isAdmin ? ADMIN_NAV : AUDITOR_NAV} portalLabel={isAdmin ? 'System Admin' : 'Security Auditor'} theme={isAdmin ? undefined : 'dark'}>
      <PageHeader
        title={isAdmin ? 'Auditor Reviews' : 'People to Review'}
        subtitle={isAdmin
          ? "The Security Auditors' weeks, so the people who review everyone else are reviewed too"
          : "Each person's whole week, ranked. Nobody is signed out by this list — you decide."}
        actions={!isAdmin && week === thisWeek && (
          <Button variant="secondary" onClick={refresh} disabled={busy}>Re-score this week</Button>
        )}
      />
      <div className="p-4 md:p-8 max-w-6xl space-y-5">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}

        <div className="flex flex-wrap items-center gap-3">
          <Button size="sm" variant="secondary" onClick={() => setWeek(shiftWeek(week, -1))}>← Previous week</Button>
          <div className="min-w-[13rem] text-center font-semibold text-ink">{weekLabel(week)}</div>
          <Button size="sm" variant="secondary" disabled={week >= thisWeek} onClick={() => setWeek(shiftWeek(week, 1))}>Next week →</Button>
          {!isAdmin && (
            <select aria-label="Role" value={role} onChange={(e) => setRole(e.target.value)} className={`${inputClass} !w-auto !py-2`}>
              <option value="">All roles</option>
              {Object.entries(ROLE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}s</option>)}
            </select>
          )}
          {last && last.at && (
            <span className="text-sm text-slate-400">
              Last scored {new Date(last.at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
              {last.ok === false && ' — scoring service unavailable'}
            </span>
          )}
        </div>

        {!data ? (
          <Spinner />
        ) : (
          <>
            <div className="grid gap-4 sm:grid-cols-3">
              <StatCard label="People active this week" value={data.summary.people} icon="users"
                hint={data.summary.stoppedSessions ? `${data.summary.stoppedSessions} session${data.summary.stoppedSessions === 1 ? '' : 's'} stopped by the instant check` : 'No sessions stopped this week'} />
              <StatCard label="Above the review line" value={data.summary.toReview} icon="flag" iconTone="coral"
                hint={data.summary.notYetReviewed ? `${data.summary.notYetReviewed} not reviewed yet` : 'All reviewed'} />
              <StatCard label="Action needed" value={data.summary.escalated} icon="shield" iconTone="amber" />
            </div>

            {data.people.length === 0 ? (
              <EmptyState title="Nobody to show for this week" icon="users">
                The list fills as people work. It is re-scored every hour.
              </EmptyState>
            ) : (
              <Card className="p-0 overflow-hidden">
                <div className="overflow-x-auto">
                  <table className="w-full min-w-[760px] text-sm">
                    <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                      <tr>
                        <th className="px-5 py-3 font-semibold">Person</th>
                        <th className="px-5 py-3 font-semibold">Score</th>
                        <th className="px-5 py-3 font-semibold">Why</th>
                        <th className="px-5 py-3 font-semibold">Days</th>
                        <th className="px-5 py-3 font-semibold">Status</th>
                        <th className="px-5 py-3 font-semibold" />
                      </tr>
                    </thead>
                    <tbody>
                      {data.people.map((p) => (
                        <tr key={p.id} className={`border-t border-[#F1E7D3] align-top ${p.needs_review ? 'bg-red-50/40' : ''}`}>
                          <td className="px-5 py-4">
                            <div className="font-medium text-ink">{p.full_name || p.email}</div>
                            <div className="text-xs text-slate-400">{ROLE_LABEL[p.role]}</div>
                          </td>
                          <td className="px-5 py-4">
                            <span className={`font-mono font-semibold ${p.above_limit ? 'text-red-600' : 'text-slate-500'}`}>
                              {Number(p.score).toFixed(2)}
                            </span>
                            {p.needs_review && <div className="mt-1"><Badge color="red">Review</Badge></div>}
                          </td>
                          <td className="px-5 py-4 max-w-[34ch]">
                            {[...p.rule_flags, ...(p.needs_review ? p.reasons : p.reasons.slice(0, 1))].map((r) => (
                              <div key={r.code} className="text-slate-600">{r.text}</div>
                            ))}
                            {!p.reasons.length && !p.rule_flags.length && <span className="text-slate-400">Usual pattern</span>}
                            {p.stopped_sessions > 0 && (
                              <div className="mt-2 inline-flex items-center gap-1 rounded-lg bg-amber-50 px-2 py-1 text-xs font-semibold text-amber-800">
                                {p.stopped_sessions} session{p.stopped_sessions === 1 ? '' : 's'} stopped this week by the instant check
                                {scope === 'auditor' && <Link to="/" className="ml-1 underline">see Flagged Sessions</Link>}
                              </div>
                            )}
                          </td>
                          <td className="px-5 py-4 text-slate-500">{p.sessions}</td>
                          <td className="px-5 py-4">
                            {p.case_status && CASE[p.case_status]
                              ? <Badge color={CASE[p.case_status].color}>{CASE[p.case_status].label}</Badge>
                              : <Badge color={STATUS[p.status].color}>{STATUS[p.status].label}</Badge>}
                          </td>
                          <td className="px-5 py-4 text-right">
                            <Button size="sm" variant="secondary" onClick={() => openRow(p.id)}>Open</Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            )}
          </>
        )}

        {open && (
          <div ref={detailRef}><Card>
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <h2 className="text-[17px] font-semibold text-ink">{open.review.full_name || open.review.email}</h2>
                <div className="text-sm text-slate-500">{ROLE_LABEL[open.review.role]} · Week of {weekText(open.review.week_label)}</div>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setOpen(null)}>Close</Button>
            </div>
            {open.review.parts && (() => {
              const pt = open.review.parts;
              const riseAbove = pt.change > pt.change_limit;
              const patternAbove = pt.learned > pt.learned_limit;
              const rules = open.review.rule_flags || [];
              const listed = riseAbove || patternAbove || rules.length > 0;
              const first = (open.review.full_name || '').split(' ')[0] || 'this person';
              return (
                <div className="mt-4 rounded-2xl bg-cream-100 px-4 py-3 text-sm">
                  <div className="mb-1 font-semibold text-ink">{listed ? `Why ${first} is listed` : `How ${first}'s week compares`}</div>
                  <Verdict label="Rise above their own usual" above={riseAbove} isReason={riseAbove} />
                  <Verdict label="Looks like known insider cases" above={patternAbove} isReason={patternAbove} />
                  {rules.length > 0 && (
                    <div className="flex flex-wrap items-center gap-2 py-1.5">
                      <span className="h-2.5 w-2.5 rounded-full bg-red-500" />
                      <span className="text-ink">Always-review rule for staff:</span>
                      <strong className="text-red-700">{rules.map((r) => r.text || r.label || r).join('; ')}</strong>
                    </div>
                  )}
                  <button type="button" onClick={() => setShowNumbers(!showNumbers)} className="mt-1 text-xs font-semibold text-brand-600 hover:underline">
                    {showNumbers ? 'Hide the numbers' : 'Show the numbers'}
                  </button>
                  {showNumbers && (
                    <div className="mt-2 font-mono text-xs text-slate-600">
                      Rise above usual {pt.change.toFixed(2)} (line {pt.change_limit.toFixed(2)}) · Looks like known insider cases {pt.learned.toFixed(2)} (line {pt.learned_limit.toFixed(2)})
                      <div className="mt-1 font-sans">Each line is set so that only about 1 in 100 ordinary weeks crosses it.</div>
                    </div>
                  )}
                </div>
              );
            })()}
            <div className="mt-5">
              {open.usual && open.usual.active_days >= BASELINE_DAYS
                ? <Badge color="green">Personal baseline established ({open.usual.active_days} days)</Badge>
                : <Badge color="gray">Still learning this person: {open.usual ? open.usual.active_days : 0} of {BASELINE_DAYS} days</Badge>}
            </div>
            <p className="mt-2 text-sm text-slate-600">
              {open.person && <>On ChildGuard for <strong className="text-ink">{open.person.daysOnChildGuard} day{open.person.daysOnChildGuard === 1 ? '' : 's'}</strong> · </>}
              {open.usual
                ? <>active on <strong className="text-ink">{open.usual.active_days} of the last 30 days</strong> · usual about <strong className="text-ink">{Math.round(open.usual.data_actions_per_day)}</strong> data action{Math.round(open.usual.data_actions_per_day) === 1 ? '' : 's'} a day</>
                : 'no activity in the 30 days before this week to compare with'}
            </p>
            {open.history && open.history.length > 1 && (
              <div className="mt-3 flex flex-wrap items-center gap-2 text-sm">
                <span className="text-slate-600">Last {open.history.length} weeks:</span>
                {open.history.map((h) => (
                  <span key={h.week} className={`rounded-full px-2.5 py-1 text-xs font-semibold ${h.listed ? 'bg-red-50 text-red-700' : 'bg-emerald-50 text-emerald-700'}`}>
                    {weekText(h.week, true)}: {h.listed ? 'listed' : 'not listed'}
                  </span>
                ))}
              </div>
            )}
            <div className="mt-2 overflow-x-auto">
              <table className="w-full min-w-[520px] text-sm">
                <thead className="text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr><th className="py-2">Day</th><th>Actions</th><th>Data actions</th><th>Devices</th><th>First</th><th>Last</th></tr>
                </thead>
                <tbody>
                  {open.days.map((d) => (
                    <tr key={d.day} className="border-t border-[#F1E7D3]">
                      <td className="py-2">{new Date(`${d.day}T12:00:00`).toLocaleDateString(undefined, { weekday: 'short', day: 'numeric', month: 'short' })}</td>
                      <td>{d.actions}</td><td>{d.data_actions}</td><td>{d.devices}</td><td>{d.first_at}</td><td>{d.last_at}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {open.review.status !== 'not_reviewed' && (
              <Alert variant="success" className="mt-4">
                {STATUS[open.review.status].label}: {open.review.review_note}
              </Alert>
            )}
            {open.case && (
              <div className="mt-4 rounded-2xl border border-[#F1E7D3] px-4 py-3 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-semibold text-ink">Case</span>
                  <Badge color={CASE[open.case.status].color}>{CASE[open.case.status].label}</Badge>
                </div>
                {open.case.pausedBy && <div className="mt-2 text-slate-600">Paused by {open.case.pausedBy}: &ldquo;{open.case.pauseNote}&rdquo;</div>}
                {open.case.explanation && <div className="mt-1 text-slate-600">Their explanation: &ldquo;{open.case.explanation}&rdquo;</div>}
                {open.case.decisionNote && <div className="mt-1 text-slate-600">{open.case.decidedBy}: &ldquo;{open.case.decisionNote}&rdquo;</div>}
              </div>
            )}
            <form className="mt-5 grid gap-4 sm:grid-cols-[200px_1fr_auto] sm:items-end" onSubmit={submitDecision}>
              <Field label="Decision">
                <select required value={decision.status} onChange={(e) => setDecision({ ...decision, status: e.target.value })} className={inputClass}>
                  <option value="">Choose…</option>
                  <option value="no_concern">No concern</option>
                  <option value="escalated">Take action</option>
                </select>
              </Field>
              <Field label="Note" hint="Kept in the audit log, at least 10 characters">
                <input required minLength={10} maxLength={2000} value={decision.note}
                  onChange={(e) => setDecision({ ...decision, note: e.target.value })} className={inputClass} />
              </Field>
              <Button disabled={busy || !decision.status || decision.note.trim().length < 10}>Record</Button>
            </form>
            <div className="mt-5 text-xs text-slate-400">Scored by model version {open.review.model_version}</div>
          </Card></div>
        )}
      </div>
    </Layout>
  );
}
