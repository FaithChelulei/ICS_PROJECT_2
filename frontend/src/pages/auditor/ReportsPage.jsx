import { useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { downloadReport } from '../../api/auditor';
import { PageHeader, Card, Field, inputClass, Alert, Button } from '../../components/ui.jsx';
import { AUDITOR_NAV } from './nav.js';

const REPORTS = [
  {
    id: 'audit-log',
    title: 'Audit Log',
    description: 'Every logged action: time, user, role, action, detail, and the risk score and outcome where the action was scored.',
    searchable: true,
  },
  {
    id: 'flagged-sessions',
    title: 'Flagged Sessions',
    description: 'Every session the risk model flagged: who, which device, score against threshold, the owner’s response and the review status.',
  },
  {
    id: 'consent-activity',
    title: 'Consent Activity',
    description: 'Every consent grant and revoke, plus every request refused because consent was missing. Child profile IDs only, no names.',
  },
];

const today = new Date().toISOString().slice(0, 10);

export default function ReportsPage() {
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [q, setQ] = useState('');
  const [busy, setBusy] = useState(null); // `${reportId}:${format}` while downloading
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');

  async function download(report, format) {
    setError('');
    setNotice('');
    setBusy(`${report.id}:${format}`);
    try {
      const filters = { from, to, ...(report.searchable ? { q } : {}) };
      const { rows, truncatedAt } = await downloadReport(report.id, format, filters);
      setNotice(
        truncatedAt
          ? `${report.title} downloaded — limited to the most recent ${truncatedAt} records. Narrow the date range for the rest.`
          : `${report.title} downloaded (${rows} record${rows === 1 ? '' : 's'}).`
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <Layout navItems={AUDITOR_NAV} portalLabel="Security Auditor" theme="dark">
      <PageHeader
        title="Reports"
        subtitle="Download records as CSV (for Excel) or PDF (for printing). Every download is itself recorded in the audit log."
      />

      <div className="p-8 max-w-4xl">
        {error && <Alert className="mb-6">{error}</Alert>}
        {notice && <Alert variant="success" className="mb-6">{notice}</Alert>}

        <Card className="mb-6">
          <div className="grid grid-cols-2 gap-4">
            <Field label="From" hint="Leave empty for the start of records">
              <input type="date" value={from} max={to || today} onChange={(e) => setFrom(e.target.value)} className={inputClass} />
            </Field>
            <Field label="To" hint="Inclusive. Leave empty for today">
              <input type="date" value={to} min={from || undefined} max={today} onChange={(e) => setTo(e.target.value)} className={inputClass} />
            </Field>
          </div>
        </Card>

        <div className="space-y-4">
          {REPORTS.map((report) => (
            <Card key={report.id}>
              <div className="flex items-start justify-between gap-6">
                <div className="min-w-0">
                  <div className="text-base font-semibold text-ink mb-1">{report.title}</div>
                  <p className="text-sm text-slate-500 max-w-lg">{report.description}</p>
                  {report.searchable && (
                    <div className="mt-3 max-w-sm">
                      <input
                        value={q}
                        onChange={(e) => setQ(e.target.value)}
                        className={inputClass}
                        placeholder="Optional search: email, action or detail"
                      />
                    </div>
                  )}
                </div>
                <div className="flex gap-2 shrink-0">
                  {['csv', 'pdf'].map((format) => (
                    <Button
                      key={format}
                      size="sm"
                      variant={format === 'pdf' ? 'primary' : 'secondary'}
                      disabled={busy !== null}
                      onClick={() => download(report, format)}
                    >
                      {busy === `${report.id}:${format}` ? 'Preparing…' : `Download ${format.toUpperCase()}`}
                    </Button>
                  ))}
                </div>
              </div>
            </Card>
          ))}
        </div>
      </div>
    </Layout>
  );
}
