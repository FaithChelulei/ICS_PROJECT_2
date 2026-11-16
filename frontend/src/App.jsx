import PausedPage from './pages/PausedPage.jsx';
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
import RetentionPage from './pages/admin/RetentionPage.jsx';
import UsersPage from './pages/admin/UsersPage.jsx';
import SettingsPage from './pages/admin/SettingsPage.jsx';
import ConsentManagementPage from './pages/caregiver/ConsentManagementPage.jsx';
import WeeklyReviewPage from './pages/WeeklyReviewPage.jsx';
import ApprovalsPage from './pages/admin/ApprovalsPage.jsx';
import ChildAccessPage from './pages/caregiver/ChildAccessPage.jsx';
import EducatorDashboard from './pages/educator/EducatorDashboard.jsx';
import EducatorChildPage from './pages/educator/EducatorChildPage.jsx';

// "/" renders a different dashboard per role rather than redirecting to
// three separate paths -- the role comes from the server (via /auth/me),
// never from anything the client decides.
function RoleHome() {
  const { user } = useAuth();
  if (user.role === 'Caregiver') return <CaregiverDashboard />;
  if (user.role === 'Educator') return <EducatorDashboard />;
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
        path="/paused"
        element={
          <ProtectedRoute>
            <PausedPage />
          </ProtectedRoute>
        }
      />
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
      <Route path="/caregiver/access" element={<ProtectedRoute allowedRoles={['Caregiver']}><ChildAccessPage /></ProtectedRoute>} />
      <Route path="/educator/children/:childProfileId" element={<ProtectedRoute allowedRoles={['Educator']}><EducatorChildPage /></ProtectedRoute>} />
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
        path="/auditor/weekly-review"
        element={
          <ProtectedRoute allowedRoles={['SecurityAuditor']}>
            <WeeklyReviewPage scope="auditor" />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/auditor-reviews"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <WeeklyReviewPage scope="admin" />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/approvals"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <ApprovalsPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/users"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <UsersPage />
          </ProtectedRoute>
        }
      />
      <Route
        path="/admin/settings"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <SettingsPage />
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
      <Route
        path="/admin/retention"
        element={
          <ProtectedRoute allowedRoles={['SysAdmin']}>
            <RetentionPage />
          </ProtectedRoute>
        }
      />
    </Routes>
  );
}
