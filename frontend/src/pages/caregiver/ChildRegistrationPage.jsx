import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { createChildProfile } from '../../api/children';
import { PageHeader, Field, inputClass, Button, Alert, Card, Toast } from '../../components/ui.jsx';

// Can't be born after today.
const todayIso = new Date().toISOString().slice(0, 10);

const NAV = [
  { to: '/', label: 'Dashboard' },
  { to: '/caregiver/children/new', label: 'Register a Child' },
  { to: '/caregiver/consent', label: 'Consent Management' },
];

export default function ChildRegistrationPage() {
  // developmentalRecordsConsent is opt-in (unchecked by default): without it
  // the backend refuses to store or show developmental records for this
  // child until consent is granted in Consent Management.
  const [form, setForm] = useState({
    fullName: '',
    dateOfBirth: '',
    familyBackground: '',
    developmentalRecordsConsent: false,
  });
  const [error, setError] = useState('');
  const [riskNotice, setRiskNotice] = useState(null);
  const [busy, setBusy] = useState(false);
  const [showToast, setShowToast] = useState(false);
  const navigate = useNavigate();

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await createChildProfile(form);
      if (data.riskNotice) {
        setRiskNotice(data.riskNotice);
      } else {
        setShowToast(true);
        setTimeout(() => navigate('/', { replace: true }), 1200);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader title="Register a New Child" />

      {showToast && (
        <Toast message="Child profile created successfully" onDone={() => setShowToast(false)} />
      )}

      <div className="p-8 max-w-4xl">
        {riskNotice ? (
          <Alert variant="warning">Profile created. {riskNotice}</Alert>
        ) : (
          <div className="grid grid-cols-[1fr_300px] gap-6 items-start">
            <Card>
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
                <Field label="Date of Birth">
                  <input
                    type="date"
                    required
                    max={todayIso}
                    value={form.dateOfBirth}
                    onChange={(e) => update('dateOfBirth', e.target.value)}
                    className={inputClass}
                  />
                </Field>
                <Field label="Family Background" hint="Optional">
                  <textarea
                    value={form.familyBackground}
                    onChange={(e) => update('familyBackground', e.target.value)}
                    className={inputClass}
                    rows={3}
                  />
                </Field>
                <label className="flex items-start gap-3 rounded-xl border border-[#E4D9C6] bg-white px-4 py-3.5 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={form.developmentalRecordsConsent}
                    onChange={(e) => update('developmentalRecordsConsent', e.target.checked)}
                    className="mt-1 h-4 w-4 accent-brand-600"
                  />
                  <span className="text-[15px] text-slate-700">
                    I consent to storing developmental &amp; health records for this child.
                    <span className="block text-sm text-slate-400 mt-0.5">
                      Optional. Records can&rsquo;t be added or viewed without it. You can change
                      this any time in Consent Management.
                    </span>
                  </span>
                </label>
                <Button disabled={busy}>{busy ? 'Saving…' : 'Create Profile'}</Button>
              </form>
            </Card>
            <Card className="bg-mint border-[#EFE4D0]">
              <div className="w-16 h-16 rounded-full bg-white border border-[#EFE4D0] flex items-center justify-center mx-auto mb-3 text-brand-400">
                <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
                  <circle cx="12" cy="8" r="4" />
                  <path d="M4 20c0-4 4-6 8-6s8 2 8 6" />
                </svg>
              </div>
              <div className="text-center text-base font-semibold text-ink mb-0.5">
                {form.fullName || 'New child profile'}
              </div>
              {form.dateOfBirth && (
                <div className="text-center text-sm text-slate-500 mb-5">
                  Date of Birth: {form.dateOfBirth}
                </div>
              )}
              <div className="border-t border-white/60 pt-4 mt-4 space-y-2.5 text-sm">
                <div className="flex justify-between">
                  <span className="text-slate-500">Caregiver</span>
                  <span className="font-semibold text-ink truncate ml-2">You</span>
                </div>
              </div>
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
}
