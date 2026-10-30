import { useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import {
  listRecords,
  submitRecord,
  listMyChildren,
  updateChildDetails,
  archiveChild,
  restoreChild,
} from '../../api/children';
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
  const [editing, setEditing] = useState(false);
  const [notice, setNotice] = useState('');
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
      // An archived profile refuses records too (PROFILE_ARCHIVED); the
      // archive notice below explains that, so it isn't an error either.
      const recordsPromise = listRecords(childProfileId).catch((err) => {
        if (err.code === 'CONSENT_REQUIRED' || err.code === 'PROFILE_ARCHIVED') return { blocked: err.code };
        throw err;
      });
      const [childrenData, recordsData] = await Promise.all([listMyChildren(), recordsPromise]);
      const match = childrenData.children.find(
        (c) => String(c.childProfileId) === String(childProfileId)
      );
      setChild(match || null);
      if (!recordsData.blocked) {
        setRecords(recordsData.records);
        if (recordsData.riskNotice) setRiskNotice(recordsData.riskNotice);
      } else {
        setRecords([]);
        setShowForm(false);
        setConsentMissing(recordsData.blocked === 'CONSENT_REQUIRED');
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

  const archived = Boolean(child?.archivedAt);

  async function handleRestore() {
    setError('');
    try {
      const result = await restoreChild(childProfileId);
      if (result.riskNotice) setRiskNotice(result.riskNotice);
      else setNotice('Profile restored.');
      load();
    } catch (err) {
      setError(err.message);
    }
  }

  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader
        title={child ? child.fullName : `Child Profile #${childProfileId}`}
        subtitle={child ? `Developmental Records · DOB ${child.dateOfBirth}` : 'Developmental Records'}
        actions={
          <div className="flex gap-2">
            {child && !archived && (
              <Button variant="secondary" onClick={() => setEditing((e) => !e)}>
                {editing ? 'Cancel edit' : 'Edit details'}
              </Button>
            )}
            {child && !archived && !consentMissing && (
              <Button onClick={() => setShowForm((s) => !s)}>
                {showForm ? 'Cancel' : '+ Add Record'}
              </Button>
            )}
          </div>
        }
      />

      <div className="p-8 max-w-3xl">
        {riskNotice && <Alert variant="warning" className="mb-6">{riskNotice}</Alert>}
        {error && <Alert className="mb-6">{error}</Alert>}
        {notice && <Alert variant="success" className="mb-6">{notice}</Alert>}
        {archived && (
          <Alert variant="warning" className="mb-6 flex items-center justify-between gap-4">
            <span>
              {child.anonymisedAt
                ? `This profile was archived and its identity anonymised on ${new Date(child.anonymisedAt).toLocaleDateString()} after the retention period. Its records are kept for the audit trail only.`
                : `This profile was archived on ${new Date(child.archivedAt).toLocaleDateString()}. Its data is kept but frozen: records can’t be viewed or added, and details and consent can’t change.`}
            </span>
            {!child.anonymisedAt && (
              <Button size="sm" variant="secondary" onClick={handleRestore}>
                Restore
              </Button>
            )}
          </Alert>
        )}

        {editing && child && (
          <div className="mb-6">
            <DetailsForm
              child={child}
              onSaved={(result) => {
                setEditing(false);
                if (result.riskNotice) setRiskNotice(result.riskNotice);
                else setNotice(result.updatedFields.length ? 'Details updated.' : 'Nothing was changed.');
                load();
              }}
            />
          </div>
        )}
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
        ) : consentMissing || archived ? null : records.length === 0 ? (
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

        {child && !archived && !loading && (
          <ArchiveSection
            childProfileId={childProfileId}
            onArchived={(result) => {
              setEditing(false);
              setShowForm(false);
              if (result.riskNotice) setRiskNotice(result.riskNotice);
              else setNotice('Profile archived. Nothing was deleted; you can restore it from here or the Dashboard.');
              load();
            }}
          />
        )}
      </div>
    </Layout>
  );
}

// Archiving = restricting processing (KDPA s.40(3)) instead of erasing:
// nothing is deleted, the profile is frozen, and it can be restored until
// the retention period anonymises its identity. Two-step so it can't
// happen on a stray click.
function ArchiveSection({ childProfileId, onArchived }) {
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleArchive() {
    setError('');
    setBusy(true);
    try {
      onArchived(await archiveChild(childProfileId, reason));
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <Card className="mt-10">
      <div className="text-base font-semibold text-ink mb-1">Archive this profile</div>
      <p className="text-sm text-slate-500 mb-4 max-w-xl">
        For a child who has left the programme. Nothing is deleted: the profile is frozen, its records
        can no longer be viewed or added, and it can be restored. After the retention period, the
        child’s name, date of birth and family background are anonymised.
      </p>
      {error && <Alert className="mb-4">{error}</Alert>}
      {confirming ? (
        <div className="space-y-3 max-w-xl">
          <Field label="Reason" hint="Optional. Kept with the profile, not in the audit log.">
            <input value={reason} onChange={(e) => setReason(e.target.value)} className={inputClass} maxLength={500} />
          </Field>
          <div className="flex gap-2">
            <Button variant="danger" size="sm" disabled={busy} onClick={handleArchive}>
              {busy ? 'Archiving…' : 'Yes, archive profile'}
            </Button>
            <Button variant="secondary" size="sm" disabled={busy} onClick={() => setConfirming(false)}>
              Cancel
            </Button>
          </div>
        </div>
      ) : (
        <Button variant="secondary" size="sm" onClick={() => setConfirming(true)}>
          Archive profile…
        </Button>
      )}
    </Card>
  );
}

// Correcting a child's identity details (KDPA s.26(d)). Only fields that
// actually changed are sent, so the audit log names exactly what was
// corrected.
const todayIso = new Date().toISOString().slice(0, 10);

function DetailsForm({ child, onSaved }) {
  const [form, setForm] = useState({
    fullName: child.fullName,
    dateOfBirth: child.dateOfBirth,
    familyBackground: child.familyBackground || '',
  });
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  function update(field, value) {
    setForm((f) => ({ ...f, [field]: value }));
  }

  async function handleSubmit(e) {
    e.preventDefault();
    const original = { ...child, familyBackground: child.familyBackground || '' };
    const changes = Object.fromEntries(
      Object.entries(form).filter(([key, value]) => value.trim() !== String(original[key]).trim())
    );
    if (Object.keys(changes).length === 0) {
      onSaved({ updatedFields: [] });
      return;
    }
    setError('');
    setBusy(true);
    try {
      onSaved(await updateChildDetails(child.childProfileId, changes));
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
          <Field label="Full Name">
            <input required value={form.fullName} onChange={(e) => update('fullName', e.target.value)} className={inputClass} />
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
        </div>
        <Field label="Family Background" hint="Optional. Leave empty to remove it.">
          <textarea
            value={form.familyBackground}
            onChange={(e) => update('familyBackground', e.target.value)}
            className={inputClass}
            rows={2}
          />
        </Field>
        <Button disabled={busy}>{busy ? 'Saving…' : 'Save corrections'}</Button>
      </form>
    </Card>
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
