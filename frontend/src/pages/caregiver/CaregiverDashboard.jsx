import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { CAREGIVER_NAV } from './nav.js';
import { useAuth } from '../../context/AuthContext.jsx';
import { listMyChildren } from '../../api/children';
import { me } from '../../api/auth';
import {
  PageHeader,
  Card,
  Button,
  Alert,
  EmptyState,
  Spinner,
  Avatar,
  Badge,
  firstNameOf,
} from '../../components/ui.jsx';
import Icon from '../../components/Icon.jsx';

const NAV = CAREGIVER_NAV;

function age(dateOfBirth) {
  const dob = new Date(dateOfBirth);
  if (Number.isNaN(dob.getTime())) return null;
  const diff = Date.now() - dob.getTime();
  const years = diff / (365.25 * 24 * 60 * 60 * 1000);
  return years < 1 ? `${Math.max(0, Math.round(years * 12))} mo` : `${Math.floor(years)} yr`;
}
export default function CaregiverDashboard() {
  const { user } = useAuth();
  const [children, setChildren] = useState([]);
  const [loading, setLoading] = useState(true);
  const [riskNotice, setRiskNotice] = useState(null);
  const [error, setError] = useState('');
  const [lastSignIn, setLastSignIn] = useState(null);

  useEffect(() => {
    listMyChildren()
      .then((data) => {
        setChildren(data.children);
        if (data.riskNotice) setRiskNotice(data.riskNotice);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
    me().then((data) => setLastSignIn(data.lastSignInAt)).catch(() => {}); // nice to have
  }, []);

  // Archived profiles are restricted (KDPA s.40(3)): listed separately, and
  // their page only offers Restore.
  const active = children.filter((c) => !c.archivedAt);
  const archived = children.filter((c) => c.archivedAt);

  const today = new Date().toLocaleDateString(undefined, {
    weekday: 'long',
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });

  return (
    <Layout navItems={NAV} portalLabel="Caregiver Portal">
      <PageHeader
        title={`Welcome back, ${firstNameOf(user?.fullName, user?.email)}`}
        subtitle={`${today} · Session active`}
        actions={
          <Link to="/caregiver/children/new">
            <Button>+ Add Child</Button>
          </Link>
        }
      />
      <div className="p-8 max-w-5xl">
        {riskNotice && (
          <Alert variant="warning" className="mb-6 flex items-center justify-between gap-4">
            <span>
              <strong>Security notice:</strong> {riskNotice}
            </span>
          </Alert>
        )}
        {error && <Alert className="mb-6">{error}</Alert>}

        <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">
          My Children ({active.length})
        </h2>
        {loading ? (
          <Spinner />
        ) : active.length === 0 ? (
          <EmptyState icon="user" title={`No ${archived.length ? 'active ' : ''}children yet`}>
            Their profiles will appear here once registered.{' '}
            <Link to="/caregiver/children/new" className="text-brand-600 font-semibold">
              Register one now
            </Link>
            .
          </EmptyState>
        ) : (
          <div className="grid grid-cols-3 gap-3">
            {active.map((c) => (
              <Link key={c.childProfileId} to={`/caregiver/children/${c.childProfileId}`}>
                <Card className="p-4 hover:border-brand-300 hover:shadow-md transition">
                  <div className="flex items-center gap-3">
                    <Avatar initial={c.fullName[0]} />
                    <div className="min-w-0">
                      <div className="text-[15px] font-semibold text-ink truncate">{c.fullName}</div>
                      <div className="text-sm text-slate-500 truncate">
                        {age(c.dateOfBirth) ? `Age ${age(c.dateOfBirth)} · ` : ''}DOB {c.dateOfBirth}
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex items-center justify-between gap-2 border-t border-[#F1E7D3] pt-2.5 text-sm text-slate-500">
                    {c.recordsConsent ? (
                      <>
                        <span>{c.recordCount} record{c.recordCount === 1 ? '' : 's'}</span>
                        <Badge color="green">Records on</Badge>
                      </>
                    ) : (
                      <>
                        <span>No records shown</span>
                        <Badge color="amber">Consent needed</Badge>
                      </>
                    )}
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        )}

        {!loading && active.length > 0 && (
          <div className="mt-4 flex items-center gap-2.5 rounded-xl bg-brand-50 px-4 py-3 text-sm font-medium text-brand-700">
            <Icon name="shield" />
            Only you can see your children&rsquo;s details.
            {lastSignIn && ` Your last sign-in was ${new Date(lastSignIn).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })}.`}
          </div>
        )}

        {!loading && archived.length > 0 && (
          <>
            <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mt-10 mb-3">
              Archived
            </h2>
            <div className="grid grid-cols-3 gap-3">
              {archived.map((c) => (
                <Link key={c.childProfileId} to={`/caregiver/children/${c.childProfileId}`}>
                  <Card className="p-4 opacity-70 hover:opacity-100 transition">
                    <div className="flex items-center gap-3">
                      <Avatar initial={c.fullName[0]} tone="slate" />
                      <div className="min-w-0">
                        <div className="text-[15px] font-semibold text-ink flex items-center gap-2 truncate">
                          {c.fullName}
                          <Badge color="gray">{c.anonymisedAt ? 'Anonymised' : 'Archived'}</Badge>
                        </div>
                        <div className="text-sm text-slate-400 mt-1">
                          {c.anonymisedAt
                            ? `Identity anonymised ${new Date(c.anonymisedAt).toLocaleDateString()}`
                            : `Archived ${new Date(c.archivedAt).toLocaleDateString()}`}
                        </div>
                      </div>
                    </div>
                  </Card>
                </Link>
              ))}
            </div>
          </>
        )}
      </div>
    </Layout>
  );
}
