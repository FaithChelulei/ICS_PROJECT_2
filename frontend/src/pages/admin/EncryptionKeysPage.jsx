import { useEffect, useState } from 'react';
import Layout from '../../components/Layout.jsx';
import { getEncryptionStatus, reencryptData } from '../../api/admin';
import { PageHeader, Card, Button, Alert, Badge, Spinner, StatCard } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

export default function EncryptionKeysPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [message, setMessage] = useState('');

  async function load() {
    setLoading(true);
    setError('');
    try {
      setStatus(await getEncryptionStatus());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function handleReencrypt() {
    if (!window.confirm('Re-encrypt every stored child record value with the active key?')) return;
    setBusy(true);
    setError('');
    setMessage('');
    try {
      const data = await reencryptData();
      setStatus(data.status);
      setMessage(
        data.updatedValues === 0
          ? 'Everything was already on the active key.'
          : `Re-encrypted ${data.updatedValues} value(s) in ${data.updatedRows} record(s) with key #${data.activeKeyId}.`
      );
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title="Encryption Key Management"
        subtitle="Which keys protect child data, and moving data onto a new key"
        actions={
          <Button onClick={handleReencrypt} disabled={busy || loading || !status || status.needsReencryption === 0}>
            {busy ? 'Re-encrypting…' : 'Re-encrypt to active key'}
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
              <StatCard label="Active key" value={`#${status.activeKeyId}`} accent="mint" />
              <StatCard label="Encrypted values" value={status.totalValues} hint="Child identity + records" />
              <StatCard
                label="Not on active key"
                value={status.needsReencryption}
                tone={status.needsReencryption ? 'text-amber-600' : 'text-emerald-600'}
                hint={status.needsReencryption ? 'Re-encrypt to finish rotating' : 'Rotation complete'}
                accent="peach"
              />
            </div>

            {status.missingKeys.length > 0 && (
              <Alert className="mb-6">
                Some data was encrypted with a key that is no longer configured (
                {status.missingKeys.map((k) => `#${k.id}: ${k.encryptedValues} value(s)`).join(', ')}
                ). Restore that key in backend/.env or that data cannot be read.
              </Alert>
            )}

            <Card className="p-0 overflow-hidden mb-6">
              <div className="grid grid-cols-[100px_1fr_140px_160px] bg-cream-100 border-b border-[#EFE4D0] px-5 py-3 text-xs font-semibold text-slate-500 uppercase tracking-wide gap-3">
                <span>Key</span>
                <span>Fingerprint</span>
                <span>Status</span>
                <span>Values using it</span>
              </div>
              {status.keys.map((k) => (
                <div
                  key={k.id}
                  className="grid grid-cols-[100px_1fr_140px_160px] px-5 py-4 text-sm items-center gap-3 border-b border-[#F1E7D3] last:border-0"
                >
                  <span className="font-semibold text-ink">#{k.id}</span>
                  <span className="font-mono text-slate-500">{k.fingerprint}</span>
                  <span>
                    {k.active ? (
                      <Badge color="green">Active</Badge>
                    ) : k.encryptedValues === 0 ? (
                      <Badge color="gray">Can be retired</Badge>
                    ) : (
                      <Badge color="amber">Still in use</Badge>
                    )}
                  </span>
                  <span className="text-slate-600">{k.encryptedValues}</span>
                </div>
              ))}
            </Card>

            <Card className="bg-sky">
              <h2 className="font-display text-lg font-bold text-ink mb-2">Rotating to a new key</h2>
              <ol className="list-decimal pl-5 space-y-1.5 text-[15px] text-slate-600">
                <li>
                  On the server, in the <span className="font-mono">backend</span> folder, run{' '}
                  <span className="font-mono">npm run key:new</span>. It writes a new key into{' '}
                  <span className="font-mono">.env</span> and makes it active (keys are never shown here).
                </li>
                <li>Restart the backend.</li>
                <li>Click <strong>Re-encrypt to active key</strong> above.</li>
                <li>When an old key shows “Can be retired”, delete it from <span className="font-mono">.env</span>.</li>
              </ol>
            </Card>
          </>
        )}
      </div>
    </Layout>
  );
}
