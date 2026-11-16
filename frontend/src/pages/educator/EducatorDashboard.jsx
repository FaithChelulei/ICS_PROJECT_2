import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { PageHeader, Card, Alert, Badge, Button, Spinner, EmptyState, Field, inputClass, Avatar, firstNameOf } from '../../components/ui.jsx';
import { useAuth } from '../../context/AuthContext.jsx';
import { listSharedChildren, requestChildAccess } from '../../api/educator';
import { EDUCATOR_NAV as NAV } from './nav.js';

const day = (d) => new Date(d).toLocaleDateString(undefined, { dateStyle: 'medium' });
const STATUS = {
  requested: { label: 'Requested', color: 'amber' },
  approved: { label: 'Approved', color: 'green' },
  ended: { label: 'Access ended', color: 'gray' },
};

// The Educator's home (SOFIA: optional, read-only). The educator asks for a
// child by name; the request goes to that child's parent, and the child
// appears here only once the parent grants it. The page never says whether
// a name matched anyone.
export default function EducatorDashboard() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [form, setForm] = useState({ childName: '', reason: '' });
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setData(await listSharedChildren());
    } catch (err) {
      setError(err.message);
    }
  }
  useEffect(() => { load(); }, []);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const res = await requestChildAccess(form.childName, form.reason);
      setForm({ childName: '', reason: '' });
      setMessage(res.message);
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  const shared = data ? data.children : [];
  const asks = data ? data.asks : [];

  return (
    <Layout navItems={NAV} portalLabel="Educator Portal">
      <PageHeader title={`Welcome, ${firstNameOf(user?.fullName, user?.email)}`} />
      <div className="p-4 md:p-8 max-w-5xl space-y-6">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}

        <section>
          <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Children ({shared.length})</h2>
          {!data ? <Spinner /> : shared.length === 0 ? (
            <EmptyState icon="users" title="No children yet" />
          ) : (
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {shared.map((c) => (
                <Link key={c.accessId} to={`/educator/children/${c.childProfileId}`}>
                  <Card className="p-4 hover:border-brand-300 hover:shadow-md transition">
                    <div className="flex items-center gap-3">
                      <Avatar initial={c.fullName[0]} />
                      <div className="min-w-0">
                        <div className="text-[15px] font-semibold text-ink truncate">{c.fullName}</div>
                        <div className="text-sm text-slate-500 truncate">{c.age ? `Age ${c.age}` : ''}</div>
                      </div>
                    </div>
                    <div className="mt-3 flex items-center justify-between gap-2 border-t border-[#F1E7D3] pt-2.5 text-sm text-slate-500">
                      <span>{c.recordCount} record{c.recordCount === 1 ? '' : 's'}</span>
                      <Badge color="green">Until {day(c.expiresAt)}</Badge>
                    </div>
                  </Card>
                </Link>
              ))}
            </div>
          )}
        </section>

        <section>
          <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">Ask for access to a child</h2>
          <Card>
            <form className="grid gap-4 sm:grid-cols-[260px_1fr_auto] sm:items-start" onSubmit={submit}>
              <Field label="Child&rsquo;s full name">
                <input required maxLength={200} value={form.childName} autoComplete="off"
                  onChange={(e) => setForm({ ...form, childName: e.target.value })} className={inputClass} />
              </Field>
              <Field label="Reason">
                <input required minLength={10} maxLength={500} value={form.reason}
                  onChange={(e) => setForm({ ...form, reason: e.target.value })} className={inputClass} />
              </Field>
              <Button className="sm:mt-7" disabled={busy || form.reason.trim().length < 10 || form.childName.trim().split(/\s+/).length < 2}>Send request</Button>
            </form>
            {(() => {
              const name = form.childName.trim();
              const why = [];
              if (name && name.split(/\s+/).length < 2) why.push('Enter the full name: first name and family name.');
              if (form.reason.trim() && form.reason.trim().length < 10) why.push('The reason needs at least 10 characters.');
              return why.length > 0 && <p className="mt-2 text-sm text-amber-800">{why.join(' ')}</p>;
            })()}
          </Card>
        </section>

        {asks.length > 0 && (
          <section>
            <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">My requests</h2>
            <Card>
              <ul className="divide-y divide-[#F1E7D3] text-sm">
                {asks.map((a) => (
                  <li key={a.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
                    <span className="min-w-0 text-slate-600"><span className="font-medium text-ink">{a.childName}</span>: &ldquo;{a.reason}&rdquo;</span>
                    <span className="flex items-center gap-3">
                      <span className="text-slate-400">{a.status === 'approved' && a.approvedAt ? `Approved ${day(a.approvedAt)}` : `Asked ${day(a.askedAt)}`}</span>
                      <Badge color={(STATUS[a.status] || STATUS.requested).color}>{(STATUS[a.status] || STATUS.requested).label}</Badge>
                    </span>
                  </li>
                ))}
              </ul>
            </Card>
          </section>
        )}
      </div>
    </Layout>
  );
}
