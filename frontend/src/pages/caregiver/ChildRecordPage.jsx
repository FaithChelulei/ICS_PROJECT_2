import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { listRecords, submitRecord, listMyChildren } from '../../api/children';
import { PageHeader, Field, inputClass, Button, Alert, Card, EmptyState, Spinner } from '../../components/ui.jsx';

const NAV = [
  { to: '/', label: 'Dashboard' },
  { to: '/caregiver/children/new', label: 'Register a Child' },
  { to: '/caregiver/consent', label: 'Consent Management' },
];

export default function ChildRecordPage() {
  const { childProfileId } = useParams();
  const [child, setChild] = useState(null);
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [riskNotice, setRiskNotice] = useState(null);
  const [showForm, setShowForm] = useState(false);
  // The backend refuses records for a child whose caregiver hasn't granted
  // developmental_records consent (403 CONSENT_REQUIRED) -- shown as a
  // prompt to grant it, not as an error.
  const [consentMissing, setConsentMissing] = useState(false);

  async function load() {
    setLoading(true);
    setError('');
    setConsentMissing(false);
    try {
      // Records are fetched separately so a consent refusal still lets the
      // child's name load for the header.
      const recordsPromise = listRecords(childProfileId).catch((err) => {
        if (err.code === 'CONSENT_REQUIRED') return null;
        throw err;
      });
      const [childrenData, recordsData] = await Promise.all([listMyChildren(), recordsPromise]);
      const match = childrenData.children.find(
        (c) => String(c.childProfileId) === String(childProfileId)
      );
      setChild(match || null);
      if (recordsData) {
        setRecords(recordsData.records);
        if (recordsData.riskNotice) setRiskNotice(recordsData.riskNotice);
      } else {
        setRecords([]);
        setShowForm(false);
        setConsentMissing(true);
      }
      if (childrenData.riskNotice) setRiskNotice(childrenData.riskNotice);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [childProfileId]);

  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader
        title={child ? child.fullName : `Child Profile #${childProfileId}`}
        subtitle={child ? `Developmental Records · DOB ${child.dateOfBirth}` : 'Developmental Records'}
        actions={
          !consentMissing && (
            <Button onClick={() => setShowForm((s) => !s)}>
              {showForm ? 'Cancel' : '+ Add Record'}
            </Button>
          )
        }
      />

      <div className="p-8 max-w-3xl">
        {riskNotice && <Alert variant="warning" className="mb-6">{riskNotice}</Alert>}
        {error && <Alert className="mb-6">{error}</Alert>}
        {consentMissing && (
          <Alert variant="warning" className="mb-6">
            Developmental &amp; health records can&rsquo;t be viewed or added for this child
            because consent hasn&rsquo;t been granted.{' '}
            <Link to="/caregiver/consent" className="font-semibold underline">
              Grant it in Consent Management
            </Link>
            .
          </Alert>
        )}

        {showForm && (
          <div className="mb-6">
            <RecordForm
              childProfileId={childProfileId}
              onSaved={() => {
                setShowForm(false);
                load();
              }}
            />
          </div>
        )}

        {loading ? (
          <Spinner />
        ) : consentMissing ? null : records.length === 0 ? (
          <EmptyState>No developmental records yet.</EmptyState>
        ) : (
          <Card>
            <div className="space-y-5">
              {records.map((r) => (
                <div
                  key={r.id}
                  className="flex gap-4 items-start border-b border-[#F1E7D3] pb-5 last:border-0 last:pb-0"
                >
                  <span className="text-xs font-medium text-slate-400 w-24 shrink-0 pt-0.5">
                    {new Date(r.createdAt).toLocaleDateString()}
                  </span>
                  <div>
                    <div className="text-sm font-semibold text-ink">{r.milestone}</div>
                    <div className="text-sm text-slate-500 mt-0.5">
                      Health: {r.healthIndicator} · Score: {r.assessmentScore}
                    </div>
                    {r.progressNotes && (
                      <div className="text-sm text-slate-400 mt-1">{r.progressNotes}</div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        )}
      </div>
    </Layout>
  );
}

function RecordForm({ childProfileId, onSaved }) {
  const [form, setForm] = useState({
    milestone: '',
    healthIndicator: '',
    assessmentScore: '',
    progressNotes: '',
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await submitRecord(childProfileId, form);
      onSaved();
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <Card>
      <form onSubmit={handleSubmit} className="space-y-5">
        {error && <Alert>{error}</Alert>}
        <div className="grid grid-cols-2 gap-4">
          <Field label="Milestone">
            <input
              required
              value={form.milestone}
              onChange={(e) => update('milestone', e.target.value)}
              className={inputClass}
            />
          </Field>
          <Field label="Health Indicator">
            <input
              required
              value={form.healthIndicator}
              onChange={(e) => update('healthIndicator', e.target.value)}
              className={inputClass}
            />
          </Field>
        </div>
        <Field label="Assessment Score">
          <input
            required
            type="number"
            step="0.1"
            value={form.assessmentScore}
            onChange={(e) => update('assessmentScore', e.target.value)}
            className={inputClass}
          />
        </Field>
        <Field label="Progress Notes" hint="Optional">
          <textarea
            value={form.progressNotes}
            onChange={(e) => update('progressNotes', e.target.value)}
            className={inputClass}
            rows={2}
          />
        </Field>
        <Button disabled={busy}>{busy ? 'Saving…' : 'Save Record'}</Button>
      </form>
    </Card>
  );
}
