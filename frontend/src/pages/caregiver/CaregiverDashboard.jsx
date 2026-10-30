import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import Layout from '../../components/Layout.jsx';
import { useAuth } from '../../context/AuthContext.jsx';
import { listMyChildren } from '../../api/children';
import {
  PageHeader,
  Card,
  Button,
  Alert,
  EmptyState,
  Spinner,
  StatCard,
  Avatar,
  firstNameOf,
} from '../../components/ui.jsx';

const NAV = [
  { to: '/', label: 'Dashboard' },
  { to: '/caregiver/children/new', label: 'Register a Child' },
  { to: '/caregiver/consent', label: 'Consent Management' },
];

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

  useEffect(() => {
    listMyChildren()
      .then((data) => {
        setChildren(data.children);
        if (data.riskNotice) setRiskNotice(data.riskNotice);
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  }, []);

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

        <div className="grid grid-cols-2 gap-4 mb-8">
          <StatCard label="Linked Children" value={children.length} hint="Active records" accent="mint" />
          <StatCard
            label="Security Status"
            value={riskNotice ? 'Attention' : 'Good'}
            tone={riskNotice ? 'text-amber-600' : 'text-emerald-600'}
            hint={riskNotice ? 'Review the notice above' : 'No anomalies'}
            accent="peach"
          />
        </div>

        <h2 className="text-sm font-semibold text-slate-500 uppercase tracking-wide mb-3">
          My Children
        </h2>
        {loading ? (
          <Spinner />
        ) : children.length === 0 ? (
          <EmptyState>
            No children registered yet.{' '}
            <Link to="/caregiver/children/new" className="text-brand-600 font-semibold">
              Register one now
            </Link>
            .
          </EmptyState>
        ) : (
          <div className="grid grid-cols-2 gap-4">
            {children.map((c) => (
              <Link key={c.childProfileId} to={`/caregiver/children/${c.childProfileId}`}>
                <Card className="hover:border-brand-300 hover:shadow-md transition">
                  <div className="flex items-start gap-4">
                    <Avatar initial={c.fullName[0]} size="lg" />
                    <div>
                      <div className="text-base font-semibold text-ink">{c.fullName}</div>
                      <div className="text-[15px] text-slate-500">
                        {age(c.dateOfBirth) ? `Age ${age(c.dateOfBirth)} · ` : ''}DOB {c.dateOfBirth}
                      </div>
                      <div className="text-sm text-slate-400 mt-2">
                        Registered {new Date(c.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        )}
      </div>
    </Layout>
  );
}
