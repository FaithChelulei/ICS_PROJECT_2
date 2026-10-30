import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { changePassword } from '../api/auth';
import { useAuth } from '../context/AuthContext.jsx';
import { Field, inputClass, Button, Alert, Card } from '../components/ui.jsx';

export default function ChangePasswordPage() {
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const { setMustChangePassword, logout } = useAuth();
  const navigate = useNavigate();

  async function handleSubmit(e) {
    e.preventDefault();
    setError('');
    if (newPassword !== confirm) {
      setError('New password and confirmation do not match.');
      return;
    }
    setBusy(true);
    try {
      await changePassword(currentPassword, newPassword);
      setMustChangePassword(false);
      navigate('/', { replace: true });
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-screen bg-cream flex items-center justify-center p-8">
      <div className="w-full max-w-md">
        <Card className="rounded-3xl">
          <h1 className="font-display text-2xl font-bold text-ink mb-2">Set a new password</h1>
          <p className="text-sm text-slate-500 mb-7">
            You're using a temporary password. Choose a new one to continue.
          </p>

          <form onSubmit={handleSubmit} className="space-y-5">
            {error && <Alert>{error}</Alert>}
            <Field label="Temporary / current password">
              <input
                type="password"
                required
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                className={inputClass}
              />
            </Field>
            <Field label="New password" hint="Minimum 8 characters">
              <input
                type="password"
                required
                minLength={8}
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className={inputClass}
              />
            </Field>
            <Field label="Confirm new password">
              <input
                type="password"
                required
                value={confirm}
                onChange={(e) => setConfirm(e.target.value)}
                className={inputClass}
              />
            </Field>
            <Button disabled={busy} className="w-full text-base py-3">
              {busy ? 'Saving…' : 'Change Password & Continue'}
            </Button>
          </form>

          <button
            onClick={logout}
            className="w-full mt-4 text-sm font-medium text-slate-500 hover:text-ink"
          >
            Log out instead
          </button>
        </Card>
      </div>
    </div>
  );
}
