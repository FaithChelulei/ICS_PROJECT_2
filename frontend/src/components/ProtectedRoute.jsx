import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';

// Gate used around every real screen: must be logged in, must have a role
// this route allows, and must have cleared a forced password change first
// (mirrors the server-side requirePasswordChanged middleware -- this is
// just the UI-side redirect, the backend is what actually enforces it).
export default function ProtectedRoute({ allowedRoles, children }) {
  const { ready, isAuthenticated, user } = useAuth();
  const location = useLocation();

  if (!ready) return null; // brief flash while /auth/me resolves on refresh

  if (!isAuthenticated) {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // A paused account sees only the pause page (the server refuses its data).
  if (user.paused && location.pathname !== '/paused') {
    return <Navigate to="/paused" replace />;
  }

  if (user.mustChangePassword && location.pathname !== '/change-password') {
    return <Navigate to="/change-password" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    // The page is for another role: back to the person's own home page, with
    // a message saying why (the server refuses that role's data in any case).
    return <Navigate to="/" replace state={{ refusedPage: location.pathname }} />;
  }

  return children;
}
