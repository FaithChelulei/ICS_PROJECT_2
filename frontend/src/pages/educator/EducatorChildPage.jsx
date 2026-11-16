import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { Card, Alert, Badge, Spinner, EmptyState } from '../../components/ui.jsx';
import { viewSharedRecords } from '../../api/educator';
import { EDUCATOR_NAV as NAV } from './nav.js';

const day = (d) => new Date(d).toLocaleDateString(undefined, { dateStyle: 'medium' });

// Score out of 10 as a short bar, so progress reads at a glance.
function ScoreBar({ value }) {
  const n = Math.max(0, Math.min(10, Number(value) || 0));
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 w-32 overflow-hidden rounded-full bg-cream-100">
        <div className="h-full rounded-full bg-brand-600" style={{ width: `${n * 10}%` }} />
      </div>
      <span className="text-sm font-semibold text-ink">{n}<span className="font-normal text-slate-400"> / 10</span></span>
    </div>
  );
}

// One shared child, read-only: name, age and developmental records. The
// server checks the parent's permission, the records consent and the risk
// score on every load, so a refusal here is the server's, shown plainly.
export default function EducatorChildPage() {
  const { childProfileId } = useParams();
  const [data, setData] = useState(null);
  const [refusal, setRefusal] = useState(null);

  useEffect(() => {
    setData(null);
    setRefusal(null);
    viewSharedRecords(childProfileId).then(setData).catch((err) => setRefusal(err));
  }, [childProfileId]);

  return (
    <Layout navItems={NAV} portalLabel="Educator Portal">
      <div className="p-4 md:p-8 max-w-5xl space-y-6">
        <Link to="/" className="inline-flex items-center gap-1 text-sm font-semibold text-brand-600 hover:text-brand-700">← Children</Link>
        {refusal && (
          <Alert variant={refusal.code === 'SESSION_REVOKED_RISK' ? 'warning' : 'error'}>
            <strong>{refusal.code === 'SESSION_REVOKED_RISK' ? 'Security notice: ' : 'Access refused. '}</strong>{refusal.message}
          </Alert>
        )}
        {!data && !refusal && <Spinner />}
        {data && (
          <>
            <Card className="overflow-hidden p-0">
              <div className="bg-gradient-to-br from-brand-50 via-white to-cream-100 px-6 py-7 md:px-8">
                <div className="flex flex-wrap items-center gap-5">
                  <div className="flex h-20 w-20 shrink-0 items-center justify-center rounded-3xl bg-brand-600 font-display text-3xl font-bold text-white shadow-sm">
                    {data.child.fullName[0]}
                  </div>
                  <div className="min-w-0 flex-1">
                    <h1 className="font-display text-3xl font-bold text-ink">{data.child.fullName}</h1>
                    <p className="mt-1 text-[15px] text-slate-600">{data.child.age ? `Age ${data.child.age}` : ''}</p>
                  </div>
                  <Badge color="green">Read-only · until {day(data.access.expiresAt)}</Badge>
                </div>
                <div className="mt-6 grid grid-cols-2 gap-3 sm:max-w-md">
                  <div className="rounded-2xl bg-white/80 px-4 py-3">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Records</div>
                    <div className="mt-0.5 text-2xl font-bold text-ink">{data.records.length}</div>
                  </div>
                  <div className="rounded-2xl bg-white/80 px-4 py-3">
                    <div className="text-xs uppercase tracking-wide text-slate-500">Latest score</div>
                    <div className="mt-0.5 text-2xl font-bold text-ink">{data.records[0] ? `${data.records[0].assessmentScore}/10` : '—'}</div>
                  </div>
                </div>
              </div>
            </Card>

            <section>
              <h2 className="mb-4 text-sm font-semibold uppercase tracking-wide text-slate-500">Developmental records</h2>
              {data.records.length === 0 ? (
                <EmptyState icon="file" title="No records yet" />
              ) : (
                <ol className="relative space-y-4 border-l-2 border-brand-100 pl-6 md:pl-8">
                  {data.records.map((r) => (
                    <li key={r.id} className="relative">
                      <span className="absolute -left-[33px] top-6 h-4 w-4 rounded-full border-4 border-white bg-brand-600 shadow md:-left-[41px]" />
                      <Card className="p-5 md:p-6">
                        <div className="flex flex-wrap items-start justify-between gap-3">
                          <div className="min-w-0">
                            <div className="text-xs font-semibold uppercase tracking-wide text-brand-600">{day(r.createdAt)}</div>
                            <h3 className="mt-1 text-lg font-semibold text-ink">{r.milestone}</h3>
                          </div>
                          <Badge color="green">{r.healthIndicator}</Badge>
                        </div>
                        <div className="mt-4"><ScoreBar value={r.assessmentScore} /></div>
                        {r.progressNotes && (
                          <p className="mt-4 rounded-xl bg-cream-100/70 px-4 py-3 text-[15px] text-slate-700">{r.progressNotes}</p>
                        )}
                      </Card>
                    </li>
                  ))}
                </ol>
              )}
            </section>
          </>
        )}
      </div>
    </Layout>
  );
}
