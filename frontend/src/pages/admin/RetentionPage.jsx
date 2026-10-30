import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { getRetentionStatus, applyRetention } from '../../api/admin';
import { PageHeader, Card, Button, Alert, Spinner, StatCard } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

// KDPA s.39 (limitation to retention). Only ARCHIVED child profiles are in
// scope: once archived for longer than the retention period, their identity
// is anonymised. Active children are never touched, and no child data is
// shown here -- only counts.
export default function RetentionPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      setStatus(await getRetentionStatus());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleApply() {
    if (!window.confirm(`Anonymise the identity of ${status.due} archived profile(s)? This cannot be undone.`)) return;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const data = await applyRetention();
      setStatus(data.status);
      setMessage(`Anonymised ${data.anonymised} profile(s). Their records and the audit trail are kept, linked only to the profile number.`);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title="Data Retention"
        subtitle="Anonymising archived child profiles once they are no longer needed (Kenya Data Protection Act s.39)"
        actions={
          <Button variant="danger" onClick={handleApply} disabled={busy || loading || !status || status.due === 0}>
            {busy ? 'Anonymising…' : status && status.due ? `Anonymise ${status.due} profile(s)` : 'Nothing due'}
          </Button>
        }
      />
      <div className="p-8 max-w-4xl">
        {error && <Alert className="mb-6">{error}</Alert>}
        {message && <Alert variant="success" className="mb-6">{message}</Alert>}

        {loading || !status ? (
          <Spinner />
        ) : (
          <>
            <div className="grid grid-cols-3 gap-4 mb-6">
              <StatCard
                label="Archived profiles"
                value={status.archived}
                hint={status.oldest_archived_at ? `Oldest archived ${new Date(status.oldest_archived_at).toLocaleDateString()}` : 'None waiting'}
                accent="mint"
              />
              <StatCard
                label="Past retention period"
                value={status.due}
                tone={status.due ? 'text-amber-600' : 'text-emerald-600'}
                hint={`Archived over ${status.retentionDays} day(s) ago`}
                accent="peach"
              />
              <StatCard label="Already anonymised" value={status.anonymised} hint="Identity removed, records kept" />
            </div>

            <Card className="bg-sky">
              <h2 className="font-display text-lg font-bold text-ink mb-2">How retention works</h2>
              <ul className="list-disc pl-5 space-y-1.5 text-[15px] text-slate-600">
                <li>A caregiver archives a profile when a child leaves the programme. Nothing is deleted, and it can be restored.</li>
                <li>
                  After <strong>{status.retentionDays} day(s)</strong> archived (<span className="font-mono">RETENTION_DAYS</span>{' '}
                  in <span className="font-mono">backend/.env</span>), the child’s name, date of birth and family background are
                  replaced with a placeholder.
                </li>
                <li>Developmental records, consent history and the audit trail stay, linked only to the profile number.</li>
                <li>Active profiles are never affected. Every run is written to the audit log.</li>
                <li>
                  To run this on a schedule instead, use <span className="font-mono">npm run retention:apply</span> in{' '}
                  <span className="font-mono">backend/</span>.
                </li>
              </ul>
            </Card>
          </>
        )}
      </div>
    </Layout>
  );
}
