import { useState } from 'react';
import { Link } from 'react-router-dom';
import { registerRequest } from '../api/auth';
import { Field, inputClass, Button, Alert, Card } from '../components/ui.jsx';
import PrivacyNotice, { PRIVACY_NOTICE_VERSION } from '../components/PrivacyNotice.jsx';

export default function RegisterPage() {
  const [form, setForm] = useState({ fullName: '', email: '', requestedRole: 'Caregiver', reason: '' });
  const [done, setDone] = useState(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [noticeAccepted, setNoticeAccepted] = useState(false);

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await registerRequest({ ...form, privacyNoticeVersion: PRIVACY_NOTICE_VERSION });
      setDone(data.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-cream flex items-center justify-center p-8">
      <div className="w-full max-w-md">
        <Card className="rounded-3xl">
          <h1 className="font-display text-2xl font-bold text-ink mb-2">Request access</h1>
          <p className="text-sm text-slate-500 mb-7">
            A System Administrator reviews every request before an account is created.
          </p>

          {done ? (
            <Alert variant="success">{done}</Alert>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-5">
              {error && <Alert>{error}</Alert>}
              <Field label="Full Name">
                <input
                  required
                  value={form.fullName}
                  onChange={(e) => update('fullName', e.target.value)}
                  className={inputClass}
                />
              </Field>
              <Field label="Email Address">
                <input
                  type="email"
                  required
                  value={form.email}
                  onChange={(e) => update('email', e.target.value)}
                  className={inputClass}
                />
              </Field>
              <Field label="Role">
                <select
                  value={form.requestedRole}
                  onChange={(e) => update('requestedRole', e.target.value)}
                  className={inputClass}
                >
                  <option value="Caregiver">Caregiver</option>
                  <option value="SecurityAuditor">Security Auditor</option>
                </select>
              </Field>
              <Field label="Reason (optional)">
                <textarea
                  value={form.reason}
                  onChange={(e) => update('reason', e.target.value)}
                  className={inputClass}
                  rows={3}
                />
              </Field>
              <PrivacyNotice variant="account" accepted={noticeAccepted} onChange={setNoticeAccepted} />
              <Button disabled={busy || !noticeAccepted} className="w-full text-base py-3">
                {busy ? 'Submitting…' : 'Submit Request'}
              </Button>
            </form>
          )}
        </Card>

        <div className="mt-6 text-center text-sm text-slate-500">
          <Link to="/login" className="text-brand-600 font-semibold hover:text-brand-700">
            ← Back to sign in
          </Link>
        </div>
      </div>
    </div>
  );
}
