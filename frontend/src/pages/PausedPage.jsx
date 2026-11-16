import { useEffect, useState } from 'react';
import { Card, Button, Alert, Spinner } from '../components/ui.jsx';
import { useAuth } from '../context/AuthContext.jsx';
import { getPausedCase, sendExplanation } from '../api/auth';
import { inputClass } from '../components/ui.jsx';

// What a person sees while their account is paused until verified
// (db/013_account_cases.sql). No menu and no data: the server refuses every
// data request from a paused account. They can only explain and sign out.
export default function PausedPage() {
  const { logout } = useAuth();
  const [data, setData] = useState(null);
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const load = () => getPausedCase().then(setData).catch((err) => setError(err.message));
  useEffect(() => { load(); }, []);

  async function submit(e) {
    e.preventDefault();
    setBusy(true);
    setError('');
    try {
      await sendExplanation(text);
      setText('');
      await load();
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-cream flex items-center justify-center p-6">
      <div className="w-full max-w-xl">
        <Card className="rounded-3xl p-8">
          <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-2xl bg-amber-50 text-2xl">⏸</div>
          <h1 className="font-display text-2xl font-bold text-ink">Your access is paused</h1>
          {!data && !error && <Spinner />}
          {error && <Alert className="mt-4">{error}</Alert>}
          {data && !data.paused && (
            <p className="mt-3 text-[15px] text-slate-600">Your access is no longer paused. Sign out and sign in again to continue.</p>
          )}
          {data && data.paused && (
            <>
              <p className="mt-3 text-[15px] text-slate-600">
                Your activity{data.week ? ` in the week of ${data.week.replace('/', ' to ')}` : ''} was well above your usual,
                so an administrator is checking it. While this is checked you cannot open any records.
              </p>
              {data.status === 'explained' ? (
                <Alert variant="success" className="mt-5">
                  Thank you. Your explanation was sent{data.explainedAt ? ` on ${new Date(data.explainedAt).toLocaleString()}` : ''}.
                  An administrator will review it, and you can use ChildGuard again once it is verified.
                  <div className="mt-2 text-ink">&ldquo;{data.explanation}&rdquo;</div>
                </Alert>
              ) : (
                <form onSubmit={submit} className="mt-5 space-y-3">
                  <label className="block text-sm font-semibold text-ink" htmlFor="why">What were you doing?</label>
                  <textarea id="why" required minLength={10} rows={4} value={text} onChange={(e) => setText(e.target.value)}
                    className={inputClass} placeholder="For example: end-of-term progress reports for my PP1 class" />
                  <Button disabled={busy || text.trim().length < 10} className="w-full">{busy ? 'Sending…' : 'Send explanation'}</Button>
                </form>
              )}
            </>
          )}
          <button type="button" onClick={logout} className="mt-6 text-sm font-semibold text-brand-600 hover:underline">Sign out</button>
        </Card>
      </div>
    </div>
  );
}
