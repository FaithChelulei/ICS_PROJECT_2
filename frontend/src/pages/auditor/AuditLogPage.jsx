import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { listAuditLog } from '../../api/auditor';
import { PageHeader, Card, Field, inputClass, Alert, EmptyState, Spinner, Badge, StatCard } from '../../components/ui.jsx';

const NAV = [
  { to: '/', label: 'Flagged Sessions' },
  { to: '/auditor/audit-log', label: 'Audit Log' },
];

function outcomeBadge(entry) {
  if (entry.is_flagged === true) return <Badge color="red">Flagged</Badge>;
  if (entry.is_flagged === false) return <Badge color="green">Allowed</Badge>;
  return <Badge color="gray">Unscored</Badge>;
}
export default function AuditLogPage() {
  const [entries, setEntries] = useState([]);
  const [totalEvents, setTotalEvents] = useState(0);
  const [q, setQ] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  async function load(query) {
    setLoading(true);
    setError('');
    try {
      const params = {};
      if (query) params.q = query;
      const data = await listAuditLog(params);
      setEntries(data.entries);
      setTotalEvents(data.totalEvents);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function handleSearch(e) {
    e.preventDefault();
    load(q);
  }

  const flaggedCount = entries.filter((e) => e.is_flagged).length;
  return (
    <Layout navItems={NAV} portalLabel="Security Auditor" theme="dark">
      <PageHeader title="Audit Log" subtitle="A full record of access events" />

      <div className="p-8">
        {error && <Alert className="mb-6">{error}</Alert>}

        <div className="grid grid-cols-3 gap-4 mb-6">
          <StatCard label="Total Events (all time)" value={totalEvents} />
          <StatCard label="Flagged (this view)" value={flaggedCount} tone="text-red-600" />
          <StatCard label="Showing" value={entries.length} hint={`of ${totalEvents} total`} />
        </div>

        <form onSubmit={handleSearch} className="mb-5 flex gap-3 items-end max-w-xl">
          <div className="flex-1">
            <Field label="Search" hint="Matches user email, action, or detail">
              <input
                value={q}
                onChange={(e) => setQ(e.target.value)}
                className={inputClass}
                placeholder="e.g. amara.osei or view_own_child_records"
              />
            </Field>
          </div>
          <button
            type="submit"
            className="rounded-full bg-brand-600 text-white px-5 py-3 text-[15px] font-semibold shadow-sm hover:bg-brand-700 transition"
          >
            Search
          </button>
        </form>
        {loading ? (
          <Spinner />
        ) : entries.length === 0 ? (
          <EmptyState>No audit events match this search.</EmptyState>
        ) : (
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <div className="min-w-[960px]">
                <div className="grid grid-cols-[130px_220px_190px_80px_100px_1fr] bg-cream-100 border-b border-[#EFE4D0] px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide gap-3">
                  <span>Time</span>
                  <span>User</span>
                  <span>Action</span>
                  <span>Risk</span>
                  <span>Outcome</span>
                  <span>Detail</span>
                </div>

                {entries.map((e) => (
                  <div
                    key={e.id}
                    className="grid grid-cols-[130px_220px_190px_80px_100px_1fr] px-5 py-3.5 text-sm items-center gap-3 border-b border-[#F1E7D3] last:border-0"
                  >
                    <span className="text-slate-400 text-xs font-mono truncate">
                      {new Date(e.created_at).toLocaleString()}
                    </span>
                    <span className="min-w-0 text-ink font-medium truncate" title={e.email || '—'}>
                      {e.email || <span className="text-slate-400 font-normal">system</span>}
                      {e.role && <span className="text-slate-400 font-normal"> ({e.role})</span>}
                    </span>
                    <span className="min-w-0 text-slate-600 truncate font-mono text-xs" title={e.action}>
                      {e.action}
                    </span>
                    <span className="font-mono text-xs text-slate-500">
                      {e.combined_score != null ? Number(e.combined_score).toFixed(2) : '—'}
                    </span>
                    <span>{outcomeBadge(e)}</span>
                    <span className="min-w-0 text-slate-400 truncate" title={e.detail || ''}>
                      {e.detail || '—'}
                    </span>
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
