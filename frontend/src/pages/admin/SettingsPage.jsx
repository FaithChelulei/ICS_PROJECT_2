import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import StepUpDialog from '../../components/StepUpDialog.jsx';
import { getSettings, updateSetting } from '../../api/admin';
import { PageHeader, Card, Field, inputClass, Alert, Button, Spinner } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

// FR-25. Only safe settings appear here. Keys and passwords are never shown
// or editable on screen.
export default function SettingsPage() {
  const [settings, setSettings] = useState(null);
  const [drafts, setDrafts] = useState({}); // key -> { value, reason }
  const [confirming, setConfirming] = useState(null); // the setting being saved
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [warning, setWarning] = useState('');

  async function load() {
    try {
      const data = await getSettings();
      setSettings(data.settings);
      setDrafts(Object.fromEntries(data.settings.map((s) => [s.key, { value: String(s.value), reason: '' }])));
    } catch (err) {
      setError(err.message);
    }
  }

  useEffect(() => {
    load();
  }, []);

  const edit = (key, field, value) => setDrafts({ ...drafts, [key]: { ...drafts[key], [field]: value } });

  // Errors reach StepUpDialog, which shows them and stays open.
  async function save(password) {
    const draft = drafts[confirming.key];
    const result = await updateSetting(confirming.key, Number(draft.value), draft.reason, password);
    setConfirming(null);
    setMessage(result.message);
    setWarning(result.riskNotice || '');
    await load();
  }

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader title="System Settings" subtitle="Changes apply straight away and are written to the audit log" />
      <div className="p-8 max-w-4xl space-y-5">
        {error && <Alert>{error}</Alert>}
        {message && <Alert variant="success">{message}</Alert>}
        {warning && <Alert variant="warning">{warning}</Alert>}

        {!settings ? (
          <Spinner />
        ) : (
          settings.map((s) => (
            <Card key={s.key}>
              <form
                className="space-y-3"
                onSubmit={(e) => {
                  e.preventDefault();
                  setMessage('');
                  setWarning('');
                  setConfirming(s);
                }}
              >
                <div>
                  <h2 className="text-[15px] font-semibold text-ink">{s.label}</h2>
                  <p className="text-sm text-slate-500">{s.description}</p>
                </div>
                <div className="grid gap-4 sm:grid-cols-[180px_1fr_auto] sm:items-end">
                  <Field label={`Value (${s.unit})`} hint={`${s.min} to ${s.max}`}>
                    <input
                      id={`setting-${s.key}`}
                      type="number"
                      required
                      step="1"
                      min={s.min}
                      max={s.max}
                      value={drafts[s.key]?.value ?? ''}
                      onChange={(e) => edit(s.key, 'value', e.target.value)}
                      className={inputClass}
                    />
                  </Field>
                  <Field label="Reason" hint="At least 10 characters">
                    <input
                      id={`reason-${s.key}`}
                      required
                      minLength={10}
                      maxLength={500}
                      value={drafts[s.key]?.reason ?? ''}
                      onChange={(e) => edit(s.key, 'reason', e.target.value)}
                      className={inputClass}
                    />
                  </Field>
                  <Button className="sm:mb-6" disabled={drafts[s.key]?.value === String(s.value)}>Save</Button>
                </div>
                {s.updatedAt && (
                  <p className="text-xs text-slate-400" title={s.reason}>
                    Last changed {new Date(s.updatedAt).toLocaleDateString()} by {s.updatedBy}
                  </p>
                )}
              </form>
            </Card>
          ))
        )}
      </div>
      {confirming && (
        <StepUpDialog
          message={`This changes the ${confirming.label.toLowerCase()} for the whole system. Enter your password to continue.`}
          confirmLabel="Confirm change"
          onConfirm={save}
          onCancel={() => setConfirming(null)}
        />
      )}
    </Layout>
  );
}
