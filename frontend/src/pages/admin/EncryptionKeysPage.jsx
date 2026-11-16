import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { getEncryptionStatus } from '../../api/admin';
import { PageHeader, Card, Button, Alert, Badge, Spinner, StatCard } from '../../components/ui.jsx';
import { ADMIN_NAV as NAV } from './nav.js';

export default function EncryptionKeysPage() {
  const [status, setStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

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

  return (
    <Layout navItems={NAV} portalLabel="System Admin">
      <PageHeader
        title="Encryption Key Management"
        actions={
          <Button onClick={() => navigate('/admin/approvals?action=reencrypt_data')} disabled={loading || !status || status.needsReencryption === 0}>
            Re-encrypt to active key
          </Button>
        }
      />
      <div className="p-4 md:p-8 max-w-4xl">
        {error && <Alert className="mb-6">{error}</Alert>}

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

            {status.protection?.mode === 'azure-key-vault' ? (
              <Alert variant="success" className="mb-6">
                Protected by Azure Key Vault · master key <span className="font-mono">{status.protection.masterKey}</span>
              </Alert>
            ) : (
              <Alert variant="warning" className="mb-6">
                Keys are stored in plain form in <span className="font-mono">backend/.env</span>. Run{' '}
                <span className="font-mono">npm run key:wrap</span> to protect them with Azure Key Vault.
              </Alert>
            )}

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
          </>
        )}
      </div>
    </Layout>
  );
}
