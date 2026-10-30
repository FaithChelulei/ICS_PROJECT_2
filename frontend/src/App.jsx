import { Routes, Route } from 'react-router-dom';
import { useAuth } from './context/AuthContext.jsx';
import ProtectedRoute from './components/ProtectedRoute.jsx';
import LoginPage from './pages/LoginPage.jsx';
import RegisterPage from './pages/RegisterPage.jsx';
import ChangePasswordPage from './pages/ChangePasswordPage.jsx';
import CaregiverDashboard from './pages/caregiver/CaregiverDashboard.jsx';
import ChildRegistrationPage from './pages/caregiver/ChildRegistrationPage.jsx';
import ChildRecordPage from './pages/caregiver/ChildRecordPage.jsx';
import AuditorDashboard from './pages/auditor/AuditorDashboard.jsx';
import AuditLogPage from './pages/auditor/AuditLogPage.jsx';
import ReportsPage from './pages/auditor/ReportsPage.jsx';
import AdminPanel from './pages/admin/AdminPanel.jsx';
import EncryptionKeysPage from './pages/admin/EncryptionKeysPage.jsx';
import ConsentManagementPage from './pages/caregiver/ConsentManagementPage.jsx';

// "/" renders a different dashboard per role rather than redirecting to
// three separate paths -- the role comes from the server (via /auth/me),
// never from anything the client decides.
function RoleHome() {
  const { user } = useAuth();
  if (user.role === 'Caregiver') return <CaregiverDashboard />;
  if (user.role === 'SecurityAuditor') return <AuditorDashboard />;
  if (user.role === 'SysAdmin') return <AdminPanel />;
  return null;
}

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      <Route
        path="/change-password"
        element={
          <ProtectedRoute>
            <ChangePasswordPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <RoleHome />
          </ProtectedRoute>
        }
      />
      <Route
        path="/caregiver/children/new"
        element={
          <ProtectedRoute allowedRoles={['Caregiver']}>
            <ChildRegistrationPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/caregiver/children/:childProfileId"
        element={
          <ProtectedRoute allowedRoles={['Caregiver']}>
            <ChildRecordPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/caregiver/consent"
        element={
          <ProtectedRoute allowedRoles={['Caregiver']}>
            <ConsentManagementPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/auditor/audit-log"
        element={
          <ProtectedRoute allowedRoles={['SecurityAuditor']}>
            <AuditLogPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/auditor/reports"
        element={
          <ProtectedRoute allowedRoles={['SecurityAuditor']}>
            <ReportsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/encryption-keys"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <EncryptionKeysPage />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
