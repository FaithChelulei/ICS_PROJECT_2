import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import {
  listRegistrationRequests,
  approveRequest,
  rejectRequest,
  listLockedUsers,
  unlockAccount,
  getAdminOverview,
} from '../../api/admin';
import { useAuth } from '../../context/AuthContext.jsx';
import {
  PageHeader,
  Card,
  Button,
  Alert,
  EmptyState,
  Spinner,
  Badge,
  Avatar,
  StatCard,
  firstNameOf,
} from '../../components/ui.jsx';
import Icon from '../../components/Icon.jsx';
import { ADMIN_NAV as NAV } from './nav.js';
const TABS = [
  { id: 'requests', label: 'Access Requests' },
  { id: 'locked', label: 'Locked Accounts' },
];

const ROLE_LABEL = { Caregiver: 'caregiver', SecurityAuditor: 'auditor', SysAdmin: 'admin' };

function greeting() {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  return hour < 18 ? 'Good afternoon' : 'Good evening';
}

export default function AdminPanel() {
  const { user } = useAuth();
  const [tab, setTab] = useState('requests');
  const [overview, setOverview] = useState(null);

  // The summary is extra: if it fails, the tabs below still work.
  function loadOverview() {
    return getAdminOverview().then(setOverview).catch(() => setOverview(null));
  }

  useEffect(() => {
    loadOverview();
  }, []);

  const attention = overview ? overview.pendingRequests + overview.lockedAccounts + overview.retentionDue : 0;
  const totalUsers = overview ? overview.activeUsers.reduce((sum, r) => sum + r.n, 0) : 0;
  const roleSummary = overview
    ? overview.activeUsers.map((r) => `${r.n} ${ROLE_LABEL[r.role] || r.role}${r.n === 1 ? '' : 's'}`).join(', ')
    : '';
  // An empty list leaves room for activity beside it; a full table needs the width.
  const listEmpty = overview && (tab === 'requests' ? overview.pendingRequests : overview.lockedAccounts) === 0;

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title={`${greeting()}, ${firstNameOf(user?.fullName, user?.email)}`}
        subtitle={attention ? `${attention} item${attention === 1 ? ' needs' : 's need'} your attention` : 'Everything is running normally'}
      />
      <div className="px-8 py-6 space-y-5">
        {overview && (
          <>
            <div className="grid grid-cols-2 xl:grid-cols-4 gap-4">
              <StatCard label="Waiting for approval" value={overview.pendingRequests} icon="inbox" iconTone="coral" hint={overview.pendingRequests ? 'Review below' : 'All reviewed'} />
              <StatCard label="Locked accounts" value={overview.lockedAccounts} icon="lock" iconTone="amber" hint={overview.lockedAccounts ? 'See Locked Accounts' : 'None locked'} />
              <StatCard label="Active users" value={totalUsers} icon="users" iconTone="sky" hint={roleSummary} />
              <StatCard label="Retention due" value={overview.retentionDue} icon="clock" hint={`Past ${overview.retentionDays} days archived`} />
            </div>
            <div className={`flex items-center gap-2.5 rounded-xl px-4 py-3 text-sm font-medium ${overview.keysInVault ? 'bg-brand-50 text-brand-700' : 'bg-amber-50 text-amber-800'}`}>
              <Icon name="shield" />
              {overview.keysInVault
                ? 'Child data encrypted. Keys protected by Azure Key Vault.'
                : 'Child data encrypted. Keys are stored in a local file; move them to Azure Key Vault.'}
            </div>
          </>
        )}

        <div className={listEmpty ? 'grid xl:grid-cols-[3fr_2fr] gap-5 items-start' : 'space-y-5'}>
          <div className="min-w-0">
            <div className="flex gap-2 mb-3">
              {TABS.map((t) => (
                <button
                  key={t.id}
                  onClick={() => setTab(t.id)}
                  className={`px-3.5 py-1.5 text-sm font-medium rounded-full border transition ${
                    tab === t.id
                      ? 'bg-brand-600 text-white border-brand-600'
                      : 'bg-white text-slate-600 border-[#EFE4D0] hover:border-brand-300'
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
            {tab === 'requests' ? <RequestsTab onChanged={loadOverview} /> : <LockedTab onChanged={loadOverview} />}
          </div>

          {overview && (
            <Card className="p-5">
              <h2 className="text-[15px] font-semibold text-ink mb-3">Recent activity</h2>
              {overview.recentActivity.length === 0 ? (
                <p className="text-sm text-slate-400">Approvals, unlocks and data changes will appear here.</p>
              ) : (
                <ul className="space-y-2.5">
                  {overview.recentActivity.map((a) => (
                    <li key={`${a.at}-${a.label}`} className="flex justify-between gap-4 text-sm">
                      <span className="text-slate-600">{a.label}</span>
                      <time className="shrink-0 text-xs text-slate-400">{new Date(a.at).toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' })}</time>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          )}
        </div>
      </div>
    </Layout>
  );
}

function RequestsTab({ onChanged }) {
  const [requests, setRequests] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busyId, setBusyId] = useState(null);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const data = await listRegistrationRequests();
      setRequests(data.requests);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleApprove(id) {
    setBusyId(id);
    setMessage('');
    try {
      const data = await approveRequest(id);
      setMessage(data.message);
      await load();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  async function handleReject(id) {
    const reason = window.prompt('Reason for rejecting this request (optional):') || '';
    setBusyId(id);
    try {
      await rejectRequest(id, reason);
      await load();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div>
      {error && <Alert className="mb-6">{error}</Alert>}
      {message && <Alert variant="success" className="mb-6">{message}</Alert>}
      {requests.length === 0 ? (
        <EmptyState icon="check" title="You're all caught up">
          New access requests will appear here for you to approve.
        </EmptyState>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="grid grid-cols-[1fr_1fr_140px_1fr_170px] bg-cream-100 border-b border-[#EFE4D0] px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide gap-3">
            <span>Name</span>
            <span>Email</span>
            <span>Requested Role</span>
            <span>Reason</span>
            <span>Action</span>
          </div>

          {requests.map((r) => (
            <div
              key={r.id}
              className="grid grid-cols-[1fr_1fr_140px_1fr_170px] px-5 py-4 text-sm items-center gap-3 border-b border-[#F1E7D3] last:border-0"
            >
              <span className="flex items-center gap-2.5 text-ink font-medium truncate">
                <Avatar initial={r.full_name?.[0]?.toUpperCase()} size="sm" />
                {r.full_name}
              </span>
              <span className="text-slate-500 truncate">{r.email}</span>
              <Badge color="brand">{r.requested_role}</Badge>
              <span className="text-slate-400 truncate">{r.reason || '—'}</span>
              <div className="flex gap-2">
                <Button size="sm" disabled={busyId === r.id} onClick={() => handleApprove(r.id)}>
                  Approve
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={busyId === r.id}
                  onClick={() => handleReject(r.id)}
                >
                  Reject
                </Button>
              </div>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}

function LockedTab({ onChanged }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [busyId, setBusyId] = useState(null);

  async function load() {
    setLoading(true);
    setError('');
    try {
      const data = await listLockedUsers();
      setUsers(data.lockedUsers);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleUnlock(id) {
    setBusyId(id);
    setMessage('');
    try {
      const data = await unlockAccount(id);
      setMessage(data.message);
      await load();
      onChanged();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyId(null);
    }
  }

  if (loading) return <Spinner />;

  return (
    <div>
      {error && <Alert className="mb-6">{error}</Alert>}
      {message && <Alert variant="success" className="mb-6">{message}</Alert>}
      {users.length === 0 ? (
        <EmptyState icon="lock" title="No locked accounts">
          Accounts locked after a &ldquo;This was NOT me&rdquo; report will appear here.
        </EmptyState>
      ) : (
        <Card className="p-0 overflow-hidden">
          <div className="grid grid-cols-[1fr_140px_1fr_170px_140px] bg-cream-100 border-b border-[#EFE4D0] px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide gap-3">
            <span>Email</span>
            <span>Role</span>
            <span>Locked Reason</span>
            <span>Locked Since</span>
            <span>Action</span>
          </div>

          {users.map((u) => (
            <div
              key={u.id}
              className="grid grid-cols-[1fr_140px_1fr_170px_140px] px-5 py-4 text-sm items-center gap-3 border-b border-[#F1E7D3] last:border-0"
            >
              <span className="flex items-center gap-2.5 text-ink font-medium truncate">
                <Avatar initial={u.email?.[0]?.toUpperCase()} size="sm" />
                {u.email}
              </span>
              <Badge color="brand">{u.role}</Badge>
              <span className="text-slate-400 truncate">{u.locked_reason || '—'}</span>
              <span className="text-slate-500">{new Date(u.created_at).toLocaleDateString()}</span>
              <Button size="sm" disabled={busyId === u.id} onClick={() => handleUnlock(u.id)}>
                Unlock
              </Button>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}
