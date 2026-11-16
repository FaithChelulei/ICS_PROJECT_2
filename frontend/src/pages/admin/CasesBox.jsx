import { useEffect, useState } from 'react';
import { Card, Badge, Button, Alert, inputClass } from '../../components/ui.jsx';
import { listCases, pauseCase, decideCase } from '../../api/admin';

const ROLE = { Caregiver: 'Caregiver', Educator: 'Educator', SecurityAuditor: 'Security Auditor', SysAdmin: 'System Admin' };
const STATUS = {
  reported: { label: 'Reported', color: 'amber' },
  paused: { label: 'Paused, waiting for explanation', color: 'red' },
  explained: { label: 'Explained, ready to verify', color: 'amber' },
  verified: { label: 'Resolved: verified', color: 'green' },
  removed: { label: 'Resolved: access removed', color: 'gray' },
};
const when = (d) => new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });

// "Action needed by the Security Auditors": the cases opened when a week is
// marked "Take action" (People to Review). The admin pauses the account until
// it is verified, reads the person's explanation, and decides. Each step asks
// for the admin's password again.
export default function CasesBox({ onChanged }) {
  const [cases, setCases] = useState(null);
  const [form, setForm] = useState(null); // { id, kind: 'pause' | 'verified' | 'removed' }
  const [note, setNote] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  const load = () => listCases().then((d) => setCases(d.cases)).catch(() => setCases([]));
  useEffect(() => { load(); }, []);

  function start(id, kind) {
    setForm({ id, kind });
    setNote('');
    setPassword('');
    setError('');
    setMessage('');
  }

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      if (form.kind === 'pause') await pauseCase(form.id, note, password);
      else await decideCase(form.id, form.kind, note, password);
      setMessage({
        pause: 'Paused. Every session of that person has ended; when they sign in they can only send an explanation.',
        verified: 'Verified. The person can use ChildGuard again with their own password.',
        removed: 'Access removed. The account is locked, and any child access an educator had has ended.',
      }[form.kind]);
      setForm(null);
      await load();
      if (onChanged) onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  if (!cases || cases.length === 0) return null;
  const open = cases.filter((c) => ['reported', 'paused', 'explained'].includes(c.status));
  const closed = cases.filter((c) => !['reported', 'paused', 'explained'].includes(c.status)).slice(0, 5);

  return (
    <Card>
      <h2 className="text-[17px] font-semibold text-ink">Action needed by the Security Auditors ({open.length})</h2>
      {message && <Alert variant="success" className="mt-3">{message}</Alert>}
      <ul className="mt-3 space-y-3">
        {[...open, ...closed].map((c) => {
          const st = STATUS[c.status];
          return (
            <li key={c.id} className="rounded-2xl border border-[#F1E7D3] px-4 py-3.5">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="text-[15px] font-semibold text-ink">{c.person} <span className="font-normal text-slate-500">· {ROLE[c.role] || c.role}{c.week ? ` · week ${c.week}` : ''}</span></div>
                  <div className="mt-1 text-sm text-slate-600"><span className="font-medium">{c.reportedBy}</span> reported: &ldquo;{c.reportNote}&rdquo;</div>
                  {c.explanation && (
                    <div className="mt-2 rounded-xl bg-cream-100 px-3 py-2 text-sm text-ink">
                      <span className="font-medium">Their explanation:</span> &ldquo;{c.explanation}&rdquo;
                    </div>
                  )}
                  {c.decisionNote && <div className="mt-1 text-sm text-slate-600">{c.decidedBy}: &ldquo;{c.decisionNote}&rdquo;</div>}
                </div>
                <Badge color={st.color}>{st.label}</Badge>
              </div>
              {!c.own && ['reported', 'paused', 'explained'].includes(c.status) && form?.id !== c.id && (
                <div className="mt-3 flex flex-wrap gap-2">
                  {c.status === 'reported' && <Button size="sm" variant="danger" onClick={() => start(c.id, 'pause')}>Pause until verified</Button>}
                  <Button size="sm" onClick={() => start(c.id, 'verified')}>Verified: restore access</Button>
                  <Button size="sm" variant="secondary" onClick={() => start(c.id, 'removed')}>Not verified: remove access</Button>
                </div>
              )}
              {form?.id === c.id && (
                <form onSubmit={submit} className="mt-3 grid gap-2 sm:grid-cols-[1fr_200px_auto] sm:items-start">
                  <input required minLength={10} value={note} onChange={(e) => setNote(e.target.value)} className={inputClass}
                    placeholder={form.kind === 'pause' ? 'Why you are pausing the account' : 'How you verified it, e.g. called the centre'} />
                  <input required type="password" value={password} onChange={(e) => setPassword(e.target.value)} className={inputClass}
                    placeholder="Your password" autoComplete="current-password" />
                  <div className="flex gap-2">
                    <Button size="sm" disabled={busy || note.trim().length < 10 || !password}>
                      {{ pause: 'Pause', verified: 'Verify', removed: 'Remove access' }[form.kind]}
                    </Button>
                    <Button size="sm" variant="ghost" type="button" onClick={() => setForm(null)}>Cancel</Button>
                  </div>
                  {error && <Alert className="sm:col-span-3">{error}</Alert>}
                </form>
              )}
              <div className="mt-2 text-xs text-slate-500">
                Reported {when(c.reportedAt)}{c.pausedAt ? ` · paused ${when(c.pausedAt)} by ${c.pausedBy}` : ''}{c.explainedAt ? ` · explained ${when(c.explainedAt)}` : ''}{c.decidedAt ? ` · decided ${when(c.decidedAt)}` : ''}
              </div>
            </li>
          );
        })}
      </ul>
    </Card>
  );
}
