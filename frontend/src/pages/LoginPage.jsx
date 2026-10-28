import { useRef, useState } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { login as apiLogin, verifyMfa as apiVerifyMfa } from '../api/auth';
import { useAuth } from '../context/AuthContext.jsx';
import { Field, inputClass, Button, Alert } from '../components/ui.jsx';



function Stepper({ step }) {
  const steps = [
    { id: 'credentials', label: 'Credentials' },
    { id: 'mfa', label: 'MFA Verify' },
  ];
  return (
    <div className="flex items-center gap-3 mb-8">
      {steps.map((s, i) => {
        const active = s.id === step;
        const done = step === 'mfa' && s.id === 'credentials';
        return (
          <div key={s.id} className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <span
                className={`w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                  active || done ? 'bg-brand-600 text-white' : 'bg-cream-200 text-slate-400'
                }`}
              >
                {done ? '✓' : i + 1}
              </span>
              <span className={`text-sm font-medium ${active ? 'text-ink' : 'text-slate-400'}`}>
                {s.label}
              </span>
            </div>
            {i < steps.length - 1 && <div className="w-10 h-px bg-slate-200" />}
          </div>
        );
      })}
    </div>
  );
}
// Six individual boxes that behave as one code -- types forward, backspace
// moves back, paste fills every box at once.
function MfaBoxes({ value, onChange }) {
  const refs = useRef([]);
  const digits = value.split('');

  function setDigit(i, d) {
    const next = value.split('');
    next[i] = d;
    onChange(next.join('').slice(0, 6));
    if (d && refs.current[i + 1]) refs.current[i + 1].focus();
  }

  function handleKeyDown(i, e) {
    if (e.key === 'Backspace' && !digits[i] && refs.current[i - 1]) {
      refs.current[i - 1].focus();
    }
  }

  function handlePaste(e) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, 6);
    onChange(pasted);
  }

  return (
    <div className="flex gap-2.5" onPaste={handlePaste}>
      {Array.from({ length: 6 }).map((_, i) => (
        <input
          key={i}
          ref={(el) => (refs.current[i] = el)}
          type="text"
          inputMode="numeric"
          maxLength={1}
          value={digits[i] || ''}
          onChange={(e) => setDigit(i, e.target.value.replace(/\D/g, ''))}
          onKeyDown={(e) => handleKeyDown(i, e)}
          className="w-12 h-14 text-center text-xl font-mono font-semibold rounded-lg border border-slate-300 text-ink shadow-sm focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-100"
        />
      ))}
    </div>
  );
}
export default function LoginPage() {
  const [step, setStep] = useState('credentials');
  const [identifier, setIdentifier] = useState('');
  const [password, setPassword] = useState('');
  const [userId, setUserId] = useState(null);
  const [mfaEmail, setMfaEmail] = useState(''); // the real destination, which may differ from what was typed
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // Set by AuthContext when a session was revoked by the risk engine;
  // read once and cleared so it only shows on the screen it explains.
  const [notice] = useState(() => {
    try {
      const msg = sessionStorage.getItem('childguard_logout_reason');
      if (msg) sessionStorage.removeItem('childguard_logout_reason');
      return msg || '';
    } catch {
      return '';
    }
  });

  const { completeLogin } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  async function handleCredentials(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await apiLogin(identifier, password);
      if (data.mfaRequired) {
        setUserId(data.userId);
        setMfaEmail(data.email);
        setStep('mfa');
      } else {
        completeLogin(data);
        navigate(location.state?.from?.pathname || '/', { replace: true });
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  async function handleMfa(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      const data = await apiVerifyMfa(userId, code);
      completeLogin(data);
      navigate(location.state?.from?.pathname || '/', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="min-h-screen flex">
      <div className="hidden lg:flex w-[460px] flex-col justify-between p-12 bg-gradient-to-br from-navy-900 via-navy-800 to-brand-700 text-white shrink-0">
        <div>
          <div className="w-12 h-12 rounded-2xl bg-white/15 flex items-center justify-center mb-9">
            <svg width="22" height="22" viewBox="0 0 16 16" fill="none">
              <rect x="1.5" y="1.5" width="6" height="6" rx="1.5" fill="white" />
              <rect x="8.5" y="1.5" width="6" height="6" rx="1.5" fill="white" opacity="0.6" />
              <rect x="1.5" y="8.5" width="6" height="6" rx="1.5" fill="white" opacity="0.6" />
              <rect x="8.5" y="8.5" width="6" height="6" rx="1.5" fill="white" />
            </svg>
          </div>
          <h1 className="font-display text-[2.6rem] font-bold leading-[1.1] tracking-tight mb-5">
            ChildGuard
            <br />
            Security System
          </h1>
          <span className="inline-flex items-center rounded-full bg-coral-500/90 px-3.5 py-1.5 text-sm font-semibold">
            Keeping child data safe, always
          </span>
        </div>
        <div />
      </div>
      <div className="flex-1 flex items-center justify-center p-8 bg-cream">
        <div className="w-full max-w-[420px] bg-white rounded-3xl shadow-card p-10">
          <Stepper step={step} />

          <h2 className="font-display text-[1.75rem] font-bold text-ink mb-2">
            {step === 'credentials' ? 'Sign in to your account' : 'Verify your identity'}
          </h2>
          <p className="text-[15px] text-slate-500 mb-8">
            {step === 'credentials'
              ? 'Enter your details to continue.'
              : `Enter the 6-digit code sent to ${mfaEmail}.`}
          </p>

          {notice && step === 'credentials' && !error && (
            <Alert variant="warning" className="mb-5">{notice}</Alert>
          )}
          {error && <Alert className="mb-5">{error}</Alert>}

          {step === 'credentials' ? (
            <form onSubmit={handleCredentials} className="space-y-5">
              <Field label="Email or Username">
                <input
                  type="text"
                  required
                  autoFocus
                  value={identifier}
                  onChange={(e) => setIdentifier(e.target.value)}
                  className={inputClass}
                  placeholder="user@example.com or username"
                />
              </Field>
              <Field label="Password">
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={inputClass}
                />
              </Field>
              <Button disabled={busy} className="w-full text-base py-3.5">
                {busy ? 'Checking…' : 'Continue →'}
              </Button>
            </form>
          ) : (
            <form onSubmit={handleMfa} className="space-y-6">
              <div>
                <div className="mb-2.5 text-[15px] font-medium text-slate-700">6-digit code</div>
                <MfaBoxes value={code} onChange={setCode} />
              </div>
              <Button disabled={busy} className="w-full text-base py-3.5">
                {busy ? 'Verifying…' : 'Verify & Sign In'}
              </Button>
              <button
                type="button"
                onClick={() => setStep('credentials')}
                className="w-full text-[15px] font-medium text-slate-500 hover:text-ink"
              >
                ← Back
              </button>
            </form>
          )}

          <div className="mt-8 text-center text-[15px] text-slate-500">
            Need an account?{' '}
            <Link to="/register" className="text-brand-600 font-semibold hover:text-brand-700">
              Request access
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
