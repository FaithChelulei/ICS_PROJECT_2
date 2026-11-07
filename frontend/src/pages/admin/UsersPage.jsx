import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import StepUpDialog from '../../components/StepUpDialog.jsx';
import { useAuth } from '../../context/AuthContext.jsx';
import { listUsers, changeUserRole } from '../../api/admin';
import { PageHeader, Card, Field, inputClass, Alert, Badge, Button, Spinner } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

const ROLES = [
  { id: 'Caregiver', label: 'Caregiver' },
  { id: 'SecurityAuditor', label: 'Security Auditor' },
  { id: 'SysAdmin', label: 'System Admin' },
];
const labelOf = (role) => ROLES.find((r) => r.id === role)?.label || role;

// FR-25. The server enforces every rule shown here.
export default function UsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState(null);
  const [editing, setEditing] = useState(null); // { user, role, reason }
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [warning, setWarning] = useState('');

  async function load() {
    try {
      setUsers((await listUsers()).users);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  // Errors reach StepUpDialog, which shows them and stays open.
  async function save(password) {
    const result = await changeUserRole(editing.user.id, editing.role, editing.reason, password);
    setConfirming(false);
    setEditing(null);
    setMessage(result.message);
    setWarning(result.riskNotice || '');
    await load();
  }

  function blockedReason(u) {
    if (u.email === me?.email) return 'You';
    if (u.children > 0) return 'Has children linked';
    return null;
  }

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader title="Users and Roles" subtitle="Who can sign in, and what each person is allowed to do" />
      <div className="p-8 max-w-5xl space-y-5">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}
        {warning && <Alert variant="warning">{warning}</Alert>}

        {!users ? (
          <Spinner />
        ) : (
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[680px] text-sm">
                <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-5 py-3 font-semibold">User</th>
                    <th className="px-5 py-3 font-semibold">Role</th>
                    <th className="px-5 py-3 font-semibold">Status</th>
                    <th className="px-5 py-3 font-semibold">Children</th>
                    <th className="px-5 py-3 font-semibold" />
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.id} className="border-t border-[#F1E7D3]">
                      <td className="px-5 py-3.5">
                        <div className="font-medium text-ink">{u.full_name}</div>
                        <div className="text-xs text-slate-400">{u.email}</div>
                      </td>
                      <td className="px-5 py-3.5 text-slate-600">{labelOf(u.role)}</td>
                      <td className="px-5 py-3.5">
                        <Badge color={u.is_locked ? 'red' : 'green'}>{u.is_locked ? 'Locked' : 'Active'}</Badge>
                      </td>
                      <td className="px-5 py-3.5 font-mono text-slate-500">{u.role === 'Caregiver' ? u.children : '—'}</td>
                      <td className="px-5 py-3.5 text-right">
                        {blockedReason(u) ? (
                          <Badge color="gray">{blockedReason(u)}</Badge>
                        ) : (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                              setMessage('');
                              setWarning('');
                              setEditing({ user: u, role: ROLES.find((r) => r.id !== u.role).id, reason: '' });
                            }}
                          >
                            Change role
                          </Button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        )}

        {editing && (
          <Card>
            <form
              className="space-y-4"
              onSubmit={(e) => {
                e.preventDefault();
                setConfirming(true);
              }}
            >
              <h2 className="text-[15px] font-semibold text-ink">Change the role of {editing.user.email}</h2>
              <div className="grid gap-4 sm:grid-cols-[220px_1fr]">
                <Field label="New role">
                  <select
                    id="new-role"
                    value={editing.role}
                    onChange={(e) => setEditing({ ...editing, role: e.target.value })}
                    className={inputClass}
                  >
                    {ROLES.filter((r) => r.id !== editing.user.role).map((r) => (
                      <option key={r.id} value={r.id}>{r.label}</option>
                    ))}
                  </select>
                </Field>
                <Field label="Reason" hint="Kept as evidence, at least 10 characters">
                  <input
                    id="role-reason"
                    required
                    minLength={10}
                    maxLength={500}
                    value={editing.reason}
                    onChange={(e) => setEditing({ ...editing, reason: e.target.value })}
                    className={inputClass}
                  />
                </Field>
              </div>
              <div className="flex justify-end gap-2">
                <Button type="button" variant="secondary" onClick={() => setEditing(null)}>Cancel</Button>
                <Button>Continue</Button>
              </div>
            </form>
          </Card>
        )}
      </div>
      {confirming && (
        <StepUpDialog
          message={`This changes what ${editing.user.email} can do and signs them out. Enter your password to continue.`}
          confirmLabel="Confirm change"
          onConfirm={save}
          onCancel={() => setConfirming(false)}
        />
      )}
    </Layout>
  );
}
