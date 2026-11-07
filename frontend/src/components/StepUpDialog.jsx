import { useState } from 'react';
import { Alert, Button, Field, inputClass } from './ui.jsx';

// Asks for the admin's password before a sensitive action. `onConfirm`
// receives the password and runs the action; if the backend refuses (wrong
// password, too many tries) the message shows here and the window stays
// open, so the person can try again or cancel.
export default function StepUpDialog({ message, confirmLabel, onConfirm, onCancel }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    setBusy(true);
    try {
      await onConfirm(password);
    } catch (err) {
      setError(err.message);
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-navy-900/60 p-4" role="dialog" aria-modal="true" aria-labelledby="step-up-title">
      <form onSubmit={handleSubmit} className="w-full max-w-md rounded-2xl bg-white p-6 shadow-card space-y-4">
        <div>
          <h2 id="step-up-title" className="font-display text-xl font-bold text-ink">Confirm it&rsquo;s you</h2>
          <p className="mt-1.5 text-[15px] text-slate-500">{message}</p>
        </div>
        {error && <Alert>{error}</Alert>}
        <Field label="Password">
          <input
            type="password"
            required
            autoFocus
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className={inputClass}
          />
        </Field>
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" disabled={busy} onClick={onCancel}>Cancel</Button>
          <Button variant="danger" disabled={busy || !password}>{busy ? 'Working…' : confirmLabel}</Button>
        </div>
      </form>
    </div>
  );
}
