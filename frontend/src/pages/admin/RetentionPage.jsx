import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { getRetentionStatus, clearMonitoringData } from '../../api/admin';
import StepUpDialog from '../../components/StepUpDialog.jsx';
import { PageHeader, Card, Button, Alert, Spinner, StatCard } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

// KDPA s.39 (limitation to retention). Only ARCHIVED child profiles are in
// scope: once archived for longer than the retention period, their identity
// is anonymised. Active children are never touched, and no child data is
// shown here -- only counts.
export default function RetentionPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');
  const [clearing, setClearing] = useState(false);
  const navigate = useNavigate();

  // Errors reach StepUpDialog, which shows them and stays open.
  async function handleClear(password) {
    const res = await clearMonitoringData(password);
    setClearing(false);
    const c = res.cleared;
    setMessage(res.riskNotice || `Cleared: ${c.actions} action(s), ${c.scores} score(s), ${c.weeks} weekly review(s).`);
    setStatus((st) => ({ ...st, monitoring: res.monitoring }));
  }

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

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title="Data Retention"
        subtitle="Anonymising archived child profiles once they are no longer needed (Kenya Data Protection Act s.39)"
        actions={
          <Button variant="danger" onClick={() => navigate('/admin/approvals?action=apply_retention')} disabled={loading || !status || status.due === 0}>
            {status && status.due ? `Anonymise ${status.due} profile(s)` : 'Nothing due'}
          </Button>
        }
      />
      <div className="p-4 md:p-8 max-w-4xl">
        {error && <Alert className="mb-6">{error}</Alert>}
        {message && <Alert variant="success" className="mb-6">{message}</Alert>}

        {loading || !status ? (
          <Spinner />
        ) : (
          <>
            <div className="grid sm:grid-cols-3 gap-4 mb-6">
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
                  After <strong>{status.retentionDays} day(s)</strong> archived (set in System Settings), the child’s name, date of
                  birth and family background are replaced with a placeholder.
                </li>
                <li>Developmental records, consent history and the audit trail stay, linked only to the profile number.</li>
                <li>Active profiles are never affected. Every run is written to the audit log.</li>
                <li>
                  To run this on a schedule instead, use <span className="font-mono">npm run retention:apply</span> in{' '}
                  <span className="font-mono">backend/</span>.
                </li>
              </ul>
            </Card>

            {status.monitoring && (
              <Card className="mt-6">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div>
                    <h2 className="font-display text-lg font-bold text-ink">Monitoring details</h2>
                    <p className="mt-1 max-w-[62ch] text-[15px] text-slate-600">
                      Each recorded action keeps the device and network it came from and the risk model&rsquo;s evidence. After{' '}
                      <strong>{status.monitoring.days} day(s)</strong> (set in System Settings) these details are cleared every
                      night. The action, its score and the audit log entry are kept.
                    </p>
                  </div>
                  <Button variant="secondary" onClick={() => setClearing(true)}
                    disabled={!(status.monitoring.due.actions + status.monitoring.due.scores + status.monitoring.due.weeks)}>
                    Clear now
                  </Button>
                </div>
                <div className="mt-4 grid grid-cols-3 gap-4 text-sm">
                  <div><div className="text-slate-500">Actions due</div><div className="font-display text-2xl font-bold text-ink">{status.monitoring.due.actions}</div></div>
                  <div><div className="text-slate-500">Score evidence due</div><div className="font-display text-2xl font-bold text-ink">{status.monitoring.due.scores}</div></div>
                  <div><div className="text-slate-500">Weekly reviews due</div><div className="font-display text-2xl font-bold text-ink">{status.monitoring.due.weeks}</div></div>
                </div>
                {status.monitoring.lastRun && (
                  <div className="mt-3 text-sm text-slate-400">Last cleared {new Date(status.monitoring.lastRun.at).toLocaleString()}</div>
                )}
              </Card>
            )}
          </>
        )}
      </div>
      {clearing && (
        <StepUpDialog
          message="This clears device names, network addresses and model evidence older than the monitoring period. Enter your password to continue."
          confirmLabel="Clear now"
          onConfirm={handleClear}
          onCancel={() => setClearing(false)}
        />
      )}
    </Layout>
  );
}
