import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import StepUpDialog from '../../components/StepUpDialog.jsx';
import { PageHeader, Card, Alert, Badge, Button, Spinner, Field, inputClass, EmptyState } from '../../components/ui.jsx';
import { listApprovals, requestApproval, approveApproval, rejectApproval, reencryptData, applyRetention } from '../../api/admin';
import { ADMIN_NAV as NAV } from './nav.js';

const STATUS = {
  pending: { label: 'Waiting for a second admin', color: 'amber' },
  approved: { label: 'Approved — ready to run', color: 'green' },
  rejected: { label: 'Rejected', color: 'red' },
  used: { label: 'Done', color: 'gray' },
};

// Two-person approval (DPIA gap G3): re-encrypting all child data and
// anonymising profiles need one System Administrator to ask and a DIFFERENT
// one to approve. The server enforces it (and the database, as a CHECK);
// this page explains it and runs the approved action.
export default function ApprovalsPage() {
  const [params] = useSearchParams();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [form, setForm] = useState({ action: params.get('action') || '', reason: '' });
  const [pending, setPending] = useState(null); // { kind, id, reason, text }

  async function load() {
    try {
      setData(await listApprovals());
    } catch (err) {
      setError(err.message);
    }
  }
  useEffect(() => {
    load();
  }, []);

  async function confirm(password) {
    const { kind, id, reason } = pending;
    let res;
    if (kind === 'request') res = await requestApproval(form.action, form.reason, password);
    if (kind === 'approve') res = await approveApproval(id, reason, password);
    if (kind === 'reject') res = await rejectApproval(id, reason, password);
    if (kind === 'run') {
      const a = data.approvals.find((x) => x.id === id);
      res = a.action === 'reencrypt_data' ? await reencryptData(password, id) : await applyRetention(password, id);
    }
    setPending(null);
    setMessage(res.riskNotice || {
      request: `Request sent. ${res.otherAdmins ? 'The other System Administrators have been emailed.' : 'There is no other System Administrator yet — add one under Users and Roles.'}`,
      approve: 'Approved. The person who asked can now run it (within 24 hours).',
      reject: 'Rejected.',
      run: 'Done. The action and both people are in the audit log.',
    }[kind]);
    if (kind === 'request') setForm({ action: '', reason: '' });
    await load();
  }

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader title="Approvals" />
      <div className="p-4 md:p-8 max-w-5xl space-y-5">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}

        <Card>
          <form className="grid gap-4 sm:grid-cols-[260px_1fr_auto] sm:items-end"
            onSubmit={(e) => { e.preventDefault(); setPending({ kind: 'request', text: 'This asks another System Administrator to approve the action.' }); }}>
            <Field label="Action">
              <select required value={form.action} onChange={(e) => setForm({ ...form, action: e.target.value })} className={inputClass}>
                <option value="">Choose…</option>
                {data && Object.entries(data.actions).map(([k, v]) => <option key={k} value={k}>{v[0].toUpperCase() + v.slice(1)}</option>)}
              </select>
            </Field>
            <Field label="Reason" hint="At least 10 characters">
              <input required minLength={10} maxLength={1000} value={form.reason} onChange={(e) => setForm({ ...form, reason: e.target.value })} className={inputClass} />
            </Field>
            <Button disabled={!form.action || form.reason.trim().length < 10}>Ask for approval</Button>
          </form>
        </Card>

        {!data ? <Spinner /> : data.approvals.length === 0 ? (
          <EmptyState title="No requests yet" icon="check">Requests and decisions will appear here.</EmptyState>
        ) : (
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px] text-sm">
                <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr><th className="px-5 py-3">Action</th><th className="px-5 py-3">Asked by</th><th className="px-5 py-3">Status</th><th className="px-5 py-3" /></tr>
                </thead>
                <tbody>
                  {data.approvals.map((a) => {
                    const expired = a.expired || a.approval_expired;
                    return (
                      <tr key={a.id} className="border-t border-[#F1E7D3] align-top">
                        <td className="px-5 py-4">
                          <div className="font-medium text-ink">{a.description[0].toUpperCase() + a.description.slice(1)}</div>
                          <div className="mt-1 text-xs text-slate-400">“{a.reason}”</div>
                        </td>
                        <td className="px-5 py-4 text-slate-600">
                          {a.mine ? 'You' : a.requested_by_name}
                          <div className="text-xs text-slate-400">{new Date(a.requested_at).toLocaleString()}</div>
                        </td>
                        <td className="px-5 py-4">
                          <Badge color={expired ? 'gray' : STATUS[a.status].color}>{expired ? 'Expired' : STATUS[a.status].label}</Badge>
                          {a.decided_by_name && <div className="mt-1 text-xs text-slate-400">by {a.decided_by_name}{a.decision_reason ? `: “${a.decision_reason}”` : ''}</div>}
                        </td>
                        <td className="px-5 py-4 text-right space-x-2 whitespace-nowrap">
                          {a.status === 'pending' && !expired && !a.mine && (
                            <>
                              <Button size="sm" onClick={() => setPending({ kind: 'approve', id: a.id, reason: '', ask: true })}>Approve</Button>
                              <Button size="sm" variant="secondary" onClick={() => setPending({ kind: 'reject', id: a.id, reason: '', ask: true })}>Reject</Button>
                            </>
                          )}
                          {a.status === 'pending' && a.mine && !expired && <span className="text-xs text-slate-400">Another admin must decide</span>}
                          {a.status === 'approved' && !expired && (
                            <Button size="sm" variant="danger" onClick={() => setPending({ kind: 'run', id: a.id, text: `This will now ${a.description}.` })}>Run now</Button>
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

        {pending && pending.ask && (
          <Card>
            <form className="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-end"
              onSubmit={(e) => { e.preventDefault(); setPending({ ...pending, ask: false, text: `You are about to ${pending.kind} this request.` }); }}>
              <Field label={`Reason to ${pending.kind}`} hint="At least 10 characters">
                <input required minLength={10} maxLength={1000} autoFocus value={pending.reason}
                  onChange={(e) => setPending({ ...pending, reason: e.target.value })} className={inputClass} />
              </Field>
              <div className="flex gap-2">
                <Button type="button" variant="secondary" onClick={() => setPending(null)}>Cancel</Button>
                <Button disabled={pending.reason.trim().length < 10}>Continue</Button>
              </div>
            </form>
          </Card>
        )}
      </div>
      {pending && !pending.ask && (
        <StepUpDialog message={`${pending.text} Enter your password to continue.`} confirmLabel="Confirm"
          onConfirm={confirm} onCancel={() => setPending(null)} />
      )}
    </Layout>
  );
}
