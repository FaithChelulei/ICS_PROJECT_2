import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { PageHeader, Card, Alert, Badge, Button, Spinner, EmptyState, inputClass } from '../../components/ui.jsx';
import {
  getChildAccess, decideChildAccess, revokeChildAccess,
} from '../../api/children';
import { CAREGIVER_NAV as NAV } from './nav.js';

const when = (d) => new Date(d).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const day = (d) => new Date(d).toLocaleDateString(undefined, { dateStyle: 'medium' });
const PERIOD = { 7: '1 week', 14: '2 weeks', 21: '3 weeks', 30: '1 month', 60: '2 months', 90: '3 months' };
const STATUS = {
  pending: { label: 'Requested', color: 'amber' },
  granted: { label: 'Approved', color: 'green' },
  refused: { label: 'Refused', color: 'red' },
  revoked: { label: 'Taken back', color: 'gray' },
  expired: { label: 'Period ended', color: 'gray' },
};

// "Who can see my child": the caregiver's side of educator access. A
// verified educator asks for a child by name; nothing is shared until the
// caregiver grants it, for a fixed period (never past the 7th birthday); it
// can be taken back at any time; every request and every look is listed.
export default function ChildAccessPage() {
  const [data, setData] = useState(null);
  const [days, setDays] = useState({});
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setData(await getChildAccess());
    } catch (err) {
      setError(err.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function act(fn, done) {
    setBusy(true);
    setError('');
    setMessage('');
    try {
      await fn();
      setMessage(done);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const pending = data ? data.requests.filter((r) => r.status === 'pending') : [];
  const requests = data ? data.requests : [];

  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader title="Who Can See My Child" />
      <div className="p-4 md:p-8 max-w-5xl space-y-6">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}

        {!data ? <Spinner /> : (
          <>
            {pending.length > 0 && (
              <section>
                <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Waiting for your decision ({pending.length})</h2>
                {pending.map((r) => (
                  <Card key={r.id} className="mb-3 border-amber-200">
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      <div className="min-w-0">
                        <div className="text-[15px] font-semibold text-ink">{r.educatorName} <span className="font-normal text-slate-500">asks to see</span> {r.childName}<span className="font-normal text-slate-500">&rsquo;s records</span></div>
                        <div className="text-sm text-slate-500">{r.ecdCentre ? `Educator at ${r.ecdCentre}` : 'Educator'} · asked {when(r.requestedAt)}</div>
                        <p className="mt-2 text-sm text-slate-700">&ldquo;{r.reason}&rdquo;</p>
                      </div>
                      <div className="flex flex-wrap items-center gap-2">
                        <select aria-label="For how long" value={days[r.id] || data.defaultGrantDays} className={`${inputClass} !w-auto !py-2`}
                          onChange={(e) => setDays({ ...days, [r.id]: Number(e.target.value) })}>
                          {data.grantDays.map((d) => <option key={d} value={d}>For {PERIOD[d] || `${d} days`}</option>)}
                        </select>
                        <Button disabled={busy} onClick={() => act(() => decideChildAccess(r.id, 'grant', days[r.id] || data.defaultGrantDays), `Granted. ${r.educatorName} can now read ${r.childName}’s records, and nothing about your other children.`)}>Grant</Button>
                        <Button variant="secondary" disabled={busy} onClick={() => act(() => decideChildAccess(r.id, 'refuse'), 'Refused. Nothing was shared.')}>Refuse</Button>
                      </div>
                    </div>
                  </Card>
                ))}
              </section>
            )}

            <section>
              <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Requests ({requests.length})</h2>
              {requests.length === 0 ? (
                <EmptyState title="No requests yet" icon="check" />
              ) : (
                <Card className="p-0 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[680px] text-sm">
                      <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                        <tr>
                          <th className="px-5 py-3">Educator</th><th className="px-5 py-3">Child</th><th className="px-5 py-3">Asked</th>
                          <th className="px-5 py-3">Status</th><th className="px-5 py-3" />
                        </tr>
                      </thead>
                      <tbody>
                        {requests.map((r) => {
                          const st = STATUS[r.status] || { label: r.status, color: 'gray' };
                          return (
                            <tr key={r.id} className="border-t border-[#F1E7D3]">
                              <td className="px-5 py-3.5"><div className="font-medium text-ink">{r.educatorName}</div><div className="text-xs text-slate-400">{r.ecdCentre || ''}</div></td>
                              <td className="px-5 py-3.5 text-slate-600">{r.childName}</td>
                              <td className="px-5 py-3.5 text-slate-600">{day(r.requestedAt)}</td>
                              <td className="px-5 py-3.5">
                                <Badge color={st.color}>{st.label}</Badge>
                                {r.status === 'granted' && <div className="mt-1 text-xs text-slate-400">until {day(r.expiresAt)}</div>}
                              </td>
                              <td className="px-5 py-3.5 text-right">
                                {r.status === 'granted' && (
                                  <Button size="sm" variant="danger" disabled={busy} onClick={() => act(() => revokeChildAccess(r.id), `Access taken back. ${r.educatorName} can no longer see ${r.childName}.`)}>Take back access</Button>
                                )}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </Card>
              )}
            </section>

            <section>
              <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Who has looked</h2>
              {data.views.length === 0 ? (
                <EmptyState title="Nobody else has opened your child’s records" icon="shield" />
              ) : (
                <Card className="p-0 overflow-hidden">
                  <div className="overflow-x-auto">
                    <table className="w-full min-w-[560px] text-sm">
                      <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                        <tr><th className="px-5 py-3">When</th><th className="px-5 py-3">Who</th><th className="px-5 py-3">Child</th><th className="px-5 py-3">Result</th></tr>
                      </thead>
                      <tbody>
                        {data.views.map((v, i) => (
                          <tr key={`${v.at}-${i}`} className="border-t border-[#F1E7D3]">
                            <td className="px-5 py-3 text-slate-600">{when(v.at)}</td>
                            <td className="px-5 py-3 text-ink">{v.viewer} <span className="text-xs text-slate-400">({v.viewerRole})</span></td>
                            <td className="px-5 py-3 text-slate-600">{v.childName}</td>
                            <td className="px-5 py-3">{v.stopped ? <Badge color="red">Stopped by the security check</Badge> : <Badge color="green">Records opened</Badge>}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              )}
            </section>
          </>
        )}
      </div>
    </Layout>
  );
}
