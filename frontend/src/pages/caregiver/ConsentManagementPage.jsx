import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { listMyChildren, getConsent, setConsent } from '../../api/children';
import {
  PageHeader,
  Card,
  Button,
  Alert,
  EmptyState,
  Spinner,
  Badge,
  Avatar,
} from '../../components/ui.jsx';

const NAV = [
  { to: '/', label: 'Dashboard' },
  { to: '/caregiver/children/new', label: 'Register a Child' },
  { to: '/caregiver/consent', label: 'Consent Management' },
];

// Friendly copy for the two scopes the backend actually tracks. No
// "third-party sharing" entry here -- the app doesn't share data with
// anyone, so a toggle for it would be fiction.
const SCOPE_COPY = {
  profile_identity: 'Your child’s name, date of birth, and other identifying details stored in their profile.',
  developmental_records: 'Developmental and health records you or a clinician submit for this child. While not granted, records can’t be added or viewed.',
};

function formatDate(iso) {
  if (!iso) return null;
  return new Date(iso).toLocaleString(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  });
}

export default function ConsentManagementPage() {
  const [children, setChildren] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [data, setData] = useState(null); // { statuses, history }
  const [loadingChildren, setLoadingChildren] = useState(true);
  const [loadingConsent, setLoadingConsent] = useState(false);
  const [busyScope, setBusyScope] = useState(null);
  const [error, setError] = useState('');

  useEffect(() => {
    listMyChildren()
      .then((res) => {
        setChildren(res.children);
        if (res.children.length > 0) setSelectedId(res.children[0].childProfileId);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoadingChildren(false));
  }, []);

  useEffect(() => {
    if (!selectedId) return;
    setLoadingConsent(true);
    setError('');
    getConsent(selectedId)
      .then(setData)
      .catch((err) => setError(err.message))
      .finally(() => setLoadingConsent(false));
  }, [selectedId]);

  async function toggle(scope, nextValue) {
    setBusyScope(scope);
    setError('');
    try {
      await setConsent(selectedId, scope, nextValue);
      const fresh = await getConsent(selectedId);
      setData(fresh);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusyScope(null);
    }
  }

  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader
        title="Consent Management"
        subtitle="Control what you've consented to store for each child, and see the full history"
      />
      <div className="p-8 max-w-4xl">
        {error && <Alert className="mb-6">{error}</Alert>}

        {loadingChildren ? (
          <Spinner />
        ) : children.length === 0 ? (
          <EmptyState>Register a child first to manage their consent.</EmptyState>
        ) : (
          <>
            {children.length > 1 && (
              <div className="flex gap-2 mb-6">
                {children.map((c) => (
                  <button
                    key={c.childProfileId}
                    onClick={() => setSelectedId(c.childProfileId)}
                    className={`flex items-center gap-2 rounded-full border px-3.5 py-2 text-[15px] font-medium transition ${
                      selectedId === c.childProfileId
                        ? 'border-brand-500 bg-brand-50 text-brand-700'
                        : 'border-[#EFE4D0] bg-white text-slate-600 hover:bg-cream-100'
                    }`}
                  >
                    <Avatar initial={c.fullName[0]} size="sm" />
                    {c.fullName}
                  </button>
                ))}
              </div>
            )}

            {loadingConsent || !data ? (
              <Spinner />
            ) : (
              <>
                <div className="space-y-4 mb-10">
                  {data.statuses.map((s) => (
                    <Card key={s.scope} className="flex items-center justify-between gap-4">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="text-base font-semibold text-ink">{s.label}</span>
                          {s.required && <Badge color="brand">Required</Badge>}
                          <Badge color={s.consentGiven ? 'green' : 'gray'}>
                            {s.consentGiven ? 'Granted' : 'Not granted'}
                          </Badge>
                        </div>
                        <p className="text-sm text-slate-500 max-w-md">{SCOPE_COPY[s.scope]}</p>
                        {s.recordedAt && (
                          <p className="text-xs text-slate-400 mt-1">
                            Last updated {formatDate(s.recordedAt)}
                          </p>
                        )}
                      </div>
                      <Button
                        variant={s.consentGiven ? 'secondary' : 'primary'}
                        size="sm"
                        disabled={(s.required && s.consentGiven) || busyScope === s.scope}
                        onClick={() => toggle(s.scope, !s.consentGiven)}
                      >
                        {busyScope === s.scope
                          ? 'Saving…'
                          : s.required && s.consentGiven
                          ? 'Required'
                          : s.consentGiven
                          ? 'Revoke'
                          : 'Grant'}
                      </Button>
                    </Card>
                  ))}
                </div>

                <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">
                  Consent History
                </h2>
                {data.history.length === 0 ? (
                  <EmptyState>No consent changes recorded yet for this child.</EmptyState>
                ) : (
                  <Card className="p-0 divide-y divide-[#F1E7D3]">
                    {data.history.map((h) => (
                      <div key={h.id} className="flex items-center justify-between px-5 py-3.5">
                        <div className="text-[15px] text-ink">
                          {SCOPE_COPY[h.scope] ? h.scope.replace(/_/g, ' ') : h.scope}
                        </div>
                        <div className="flex items-center gap-3">
                          <Badge color={h.consent_given ? 'green' : 'gray'}>
                            {h.consent_given ? 'Granted' : 'Revoked'}
                          </Badge>
                          <span className="text-sm text-slate-400">{formatDate(h.recorded_at)}</span>
                        </div>
                      </div>
                    ))}
                  </Card>
                )}
              </>
            )}
          </>
        )}
      </div>
    </Layout>
  );
}
