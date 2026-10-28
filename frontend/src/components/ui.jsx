// Small shared design-system primitives (clean white cards, soft shadows,
// a lighter blue accent, generous spacing, bigger type) so every page
// shares the same look instead of repeating Tailwind classes everywhere.
import { useEffect } from 'react';

// Best-effort "first name" for a greeting -- prefers the account's real
// full_name (set at registration approval), falls back to the local part
// of the email for older accounts that predate that field.
export function firstNameOf(fullName, email) {
  if (fullName && fullName.trim()) return fullName.trim().split(/\s+/)[0];
  if (email) return email.split('@')[0].split(/[.+]/)[0];
  return 'there';
}

// A transient, auto-dismissing notification (bottom-right), distinct from
// Alert (which is a static inline banner a page keeps showing). Used for
// "this just succeeded" confirmations that shouldn't linger on screen.
export function Toast({ message, variant = 'success', onDone, durationMs = 2200 }) {
  useEffect(() => {
    const t = setTimeout(() => onDone && onDone(), durationMs);
    return () => clearTimeout(t);
  }, [onDone, durationMs]);

  const styles = {
    success: 'bg-brand-600',
    error: 'bg-red-600',
  };

  return (
    <div
      role="status"
      className={`fixed bottom-6 right-6 z-50 ${styles[variant]} text-white px-5 py-3.5 rounded-2xl shadow-lg text-[15px] font-medium animate-[fadeIn_0.15s_ease-out]`}
    >
      {message}
    </div>
  );
}

export const inputClass =
  'w-full rounded-xl border border-[#E4D9C6] bg-white px-4 py-3 text-[15px] text-ink placeholder:text-slate-400 shadow-sm transition focus:border-brand-500 focus:outline-none focus:ring-2 focus:ring-brand-100';

export function Field({ label, hint, children }) {
  return (
    <div>
      <div className="mb-1.5 text-[15px] font-medium text-slate-700">{label}</div>
      {children}
      {hint && <div className="mt-1 text-sm text-slate-400">{hint}</div>}
    </div>
  );
}

export function Button({ variant = 'primary', size = 'md', className = '', ...props }) {
  const sizes = { md: 'px-5 py-2.5 text-[15px]', sm: 'px-4 py-2 text-sm' };
  const variants = {
    primary:
      'bg-brand-600 text-white shadow-sm hover:bg-brand-700 disabled:bg-brand-300',
    secondary:
      'bg-white text-ink border border-[#E4D9C6] shadow-sm hover:bg-cream-100 disabled:text-slate-400',
    danger: 'bg-red-600 text-white shadow-sm hover:bg-red-700 disabled:bg-red-300',
    ghost: 'text-slate-500 hover:text-ink',
  };
  return (
    <button
      className={`inline-flex items-center justify-center gap-1.5 rounded-full font-semibold transition disabled:cursor-not-allowed ${sizes[size]} ${variants[variant]} ${className}`}
      {...props}
    />
  );
}
export function Card({ className = '', children }) {
  return (
    <div className={`rounded-2xl border border-[#EFE4D0] bg-white p-6 shadow-card ${className}`}>
      {children}
    </div>
  );
}

export function PageHeader({ title, subtitle, actions }) {
  return (
    <div className="flex items-center justify-between border-b border-[#EFE4D0] bg-white px-8 py-7">
      <div>
        <h1 className="font-display text-[1.7rem] font-bold text-ink tracking-tight">{title}</h1>
        {subtitle && <p className="mt-1.5 text-[15px] text-slate-500">{subtitle}</p>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

export function EmptyState({ children }) {
  return (
    <div className="rounded-2xl border border-dashed border-[#E4D9C6] bg-white px-6 py-14 text-center text-[15px] text-slate-500">
      {children}
    </div>
  );
}

const alertStyles = {
  error: 'border-red-200 bg-red-50 text-red-700',
  warning: 'border-amber-200 bg-amber-50 text-amber-800',
  success: 'border-emerald-200 bg-emerald-50 text-emerald-700',
};

export function Alert({ variant = 'error', className = '', children }) {
  return (
    <div className={`rounded-xl border px-4 py-3.5 text-[15px] ${alertStyles[variant]} ${className}`}>
      {children}
    </div>
  );
}
const badgeStyles = {
  gray: 'bg-slate-100 text-slate-600',
  green: 'bg-emerald-50 text-emerald-700',
  amber: 'bg-amber-50 text-amber-700',
  red: 'bg-red-50 text-red-700',
  brand: 'bg-brand-50 text-brand-700',
};

export function Badge({ color = 'gray', children }) {
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${badgeStyles[color]}`}
    >
      {children}
    </span>
  );
}

export function Spinner({ label = 'Loading…' }) {
  return <div className="px-8 py-10 text-[15px] text-slate-400">{label}</div>;
}

// A small metric tile used across dashboards (stat cards row). `accent`
// tints the card itself with one of the pastel tokens (mint/peach/sky) for
// the feature-grid look in the reference design -- optional, defaults to
// plain white so existing callers are unaffected.
export function StatCard({ label, value, tone = 'text-ink', hint, accent }) {
  const accents = { mint: 'bg-mint', peach: 'bg-peach', sky: 'bg-sky' };
  return (
    <Card className={`p-5 ${accent ? accents[accent] : ''}`}>
      <div className="text-[13px] font-medium text-slate-500 mb-1">{label}</div>
      <div className={`font-display text-3xl font-bold ${tone}`}>{value}</div>
      {hint && <div className="mt-1 text-sm text-slate-400">{hint}</div>}
    </Card>
  );
}

// Avatar circle with the person's initial, tinted by role.
export function Avatar({ initial, size = 'md', tone = 'brand' }) {
  const sizes = { sm: 'w-8 h-8 text-xs', md: 'w-10 h-10 text-sm', lg: 'w-12 h-12 text-lg' };
  const tones = {
    brand: 'bg-brand-100 text-brand-700',
    coral: 'bg-coral-100 text-coral-600',
    emerald: 'bg-emerald-100 text-emerald-700',
    slate: 'bg-slate-100 text-slate-600',
  };
  return (
    <div
      className={`rounded-full font-bold flex items-center justify-center shrink-0 ${sizes[size]} ${tones[tone]}`}
    >
      {initial}
    </div>
  );
}
// Styled placeholder for screens whose backend isn't built yet (Consent
// Management, Encryption Key Management, Audit Log). Honest about what's
// missing rather than showing fabricated data that looks live.
export function ComingSoon({ title, points = [] }) {
  return (
    <Card className="max-w-xl mx-auto text-center py-12 px-8">
      <div className="w-14 h-14 rounded-2xl bg-amber-50 text-amber-500 flex items-center justify-center mx-auto mb-5">
        <svg width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="4" y="10" width="16" height="10" rx="2" />
          <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        </svg>
      </div>
      <h2 className="text-xl font-bold text-ink mb-2">{title}</h2>
      <p className="text-[15px] text-slate-500 mb-6">
        This part of the system is designed but not yet built -- it needs real backend
        work (not just a new screen) before it can show live data.
      </p>
      {points.length > 0 && (
        <ul className="text-left text-[15px] text-slate-600 space-y-2.5 bg-slate-50 rounded-lg p-5">
          {points.map((p) => (
            <li key={p} className="flex gap-2.5">
              <span className="text-brand-500 font-bold shrink-0">&middot;</span>
              <span>{p}</span>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}
