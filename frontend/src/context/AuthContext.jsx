import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import { setAuthToken, setUnauthorizedHandler } from '../api/client';
import { me as fetchMe, logout as apiLogout } from '../api/auth';

const AuthContext = createContext(null);
const STORAGE_KEY = 'childguard_token';

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem(STORAGE_KEY));
  const [user, setUser] = useState(null); // { id, email, role, mustChangePassword }
  const [ready, setReady] = useState(false);

  const clearSession = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    setAuthToken(null);
    setToken(null);
    setUser(null);
  }, []);

  // Any 401 from the API (expired token, or the session was force-revoked
  // by a risk response mid-use) bounces the whole app back to login --
  // registered once, here, not per-component.
  useEffect(() => {
    setUnauthorizedHandler((data) => {
      // Tell the login screen why the user landed there (shown once).
      if (data?.code === 'SESSION_REVOKED_RISK') {
        try {
          sessionStorage.setItem('childguard_logout_reason', data.error);
        } catch {
          /* storage blocked -- the redirect still happens */
        }
      }
      clearSession();
    });
  }, [clearSession]);

  // On load (or refresh), if a token survived in localStorage, confirm it
  // still works and get the current role / mustChangePassword from the
  // server rather than trusting whatever was cached client-side.
  useEffect(() => {
    if (!token) {
      setReady(true);
      return;
    }
    setAuthToken(token);
    fetchMe()
      .then((data) => setUser(data))
      .catch(() => clearSession())
      .finally(() => setReady(true));
  }, [token, clearSession]);

  // Called once a full session exists -- either login() returned a token
  // directly (no MFA edge case) or verify-mfa did.
  function completeLogin(sessionData) {
    const { token: newToken, role, email, fullName, mustChangePassword } = sessionData;
    localStorage.setItem(STORAGE_KEY, newToken);
    setAuthToken(newToken);
    setToken(newToken);
    setUser({ role, email, fullName, mustChangePassword });
  }

  function setMustChangePassword(value) {
    setUser((u) => (u ? { ...u, mustChangePassword: value } : u));
  }

  async function logout() {
    try {
      await apiLogout();
    } catch {
      // Already logged out server-side (expired/revoked token) -- clearing
      // local state below is what actually matters to the user.
    }
    clearSession();
  }

  const value = {
    token,
    user,
    ready,
    isAuthenticated: Boolean(token && user),
    completeLogin,
    setMustChangePassword,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used within AuthProvider');
  return ctx;
}
