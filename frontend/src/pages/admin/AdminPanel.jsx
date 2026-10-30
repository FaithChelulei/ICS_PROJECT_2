import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import {
  listRegistrationRequests,
  approveRequest,
  rejectRequest,
  listLockedUsers,
  unlockAccount,
} from '../../api/admin';
import { PageHeader, Card, Button, Alert, EmptyState, Spinner, Badge, Avatar } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';
const TABS = [
  { id: 'requests', label: 'Registration Requests' },
  { id: 'locked', label: 'Locked Accounts' },
];

export default function AdminPanel() {
  const [tab, setTab] = useState('requests');

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title="Admin Panel"
        actions={
          <div className="flex gap-2">
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
        }
      />
      <div className="p-8">{tab === 'requests' ? <RequestsTab /> : <LockedTab />}</div>
    </Layout>
  );
}

function RequestsTab() {
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
        <EmptyState>No pending registration requests.</EmptyState>
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

function LockedTab() {
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
        <EmptyState>No locked accounts.</EmptyState>
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
