import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import StepUpDialog from '../../components/StepUpDialog.jsx';
import { getRiskThresholds, updateRiskThreshold } from '../../api/auditor';
import { PageHeader, Card, Field, inputClass, Alert, Badge, Button, Spinner } from '../../components/ui.jsx';
import { AUDITOR_NAV } from './nav.js';

const ROLE_LABEL = { Caregiver: 'Caregiver', SecurityAuditor: 'Security Auditor', SysAdmin: 'System Admin' };

// FR-21. The server enforces the limits, the password check and the rule
// against changing your own role; this page explains them.
export default function RiskThresholdsPage() {
  const [thresholds, setThresholds] = useState(null);
  const [editing, setEditing] = useState(null); // { role, threshold, reason, min, max }
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [warning, setWarning] = useState('');

  async function load() {
    try {
      setThresholds((await getRiskThresholds()).thresholds);
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  // Errors reach StepUpDialog, which shows them and stays open.
  async function save(password) {
    const result = await updateRiskThreshold(editing.role, Number(editing.threshold), editing.reason, password);
    setConfirming(false);
    setEditing(null);
    setMessage(result.message);
    setWarning(result.riskNotice || '');
    await load();
  }

  return (
    <Layout navItems={AUDITOR_NAV} portalLabel="Security Auditor" theme="dark">
      <PageHeader title="Risk Thresholds" subtitle="The score at which a session is flagged and ended, for each role" />
      <div className="p-8 max-w-4xl space-y-5">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}
        {warning && <Alert variant="warning">{warning}</Alert>}
        <Alert variant="warning">
          A higher limit flags fewer sessions, so real misuse may be missed. A lower limit signs out more people doing
          normal work. Every change is logged and all System Administrators are emailed.
        </Alert>

        {!thresholds ? (
          <Spinner />
        ) : (
          <Card className="p-0 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full min-w-[640px] text-sm">
                <thead className="bg-cream-100 text-left text-xs uppercase tracking-wide text-slate-500">
                  <tr>
                    <th className="px-5 py-3 font-semibold">Role</th>
                    <th className="px-5 py-3 font-semibold">Current limit</th>
                    <th className="px-5 py-3 font-semibold">Calibrated</th>
                    <th className="px-5 py-3 font-semibold">Allowed</th>
                    <th className="px-5 py-3 font-semibold" />
                  </tr>
                </thead>
                <tbody>
                  {thresholds.map((t) => (
                    <tr key={t.role} className="border-t border-[#F1E7D3] align-top">
                      <td className="px-5 py-4">
                        <div className="font-medium text-ink">{ROLE_LABEL[t.role]}</div>
                        {t.updatedAt && (
                          <div className="mt-1 max-w-[30ch] text-xs text-slate-400" title={t.reason}>
                            Changed {new Date(t.updatedAt).toLocaleDateString()} by {t.updatedBy}
                          </div>
                        )}
                      </td>
                      <td className="px-5 py-4 font-mono font-semibold text-ink">{t.threshold.toFixed(2)}</td>
                      <td className="px-5 py-4 font-mono text-slate-500">{t.defaultThreshold.toFixed(2)}</td>
                      <td className="px-5 py-4 font-mono text-slate-500">{t.min.toFixed(2)} to {t.max.toFixed(2)}</td>
                      <td className="px-5 py-4 text-right">
                        {t.editable ? (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => {
                              setMessage('');
                              setWarning('');
                              setEditing({ role: t.role, threshold: t.threshold.toFixed(2), reason: '', min: t.min, max: t.max });
                            }}
                          >
                            Change
                          </Button>
                        ) : (
                          <Badge color="gray">Your own role</Badge>
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
              <h2 className="text-[15px] font-semibold text-ink">Change the {ROLE_LABEL[editing.role]} limit</h2>
              <div className="grid gap-4 sm:grid-cols-[180px_1fr]">
                <Field label="New limit" hint={`${editing.min.toFixed(2)} to ${editing.max.toFixed(2)}`}>
                  <input
                    id="new-threshold"
                    type="number"
                    required
                    step="0.01"
                    min={editing.min}
                    max={editing.max}
                    value={editing.threshold}
                    onChange={(e) => setEditing({ ...editing, threshold: e.target.value })}
                    className={inputClass}
                  />
                </Field>
                <Field label="Reason" hint="Kept as evidence, at least 10 characters">
                  <input
                    id="threshold-reason"
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
          message={`This changes when ${ROLE_LABEL[editing.role]} sessions are flagged. Enter your password to continue.`}
          confirmLabel="Confirm change"
          onConfirm={save}
          onCancel={() => setConfirming(false)}
        />
      )}
    </Layout>
  );
}
