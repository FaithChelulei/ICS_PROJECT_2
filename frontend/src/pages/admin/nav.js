// Sidebar for every System Admin page (one place, so a new page only has to
// be added here).
export const ADMIN_NAV = [
  { to: '/', label: 'Overview', icon: 'home' },
  { to: '/admin/users', label: 'Users and Roles', icon: 'users' },
  { to: '/admin/encryption-keys', label: 'Encryption Keys', icon: 'key' },
  { to: '/admin/retention', label: 'Data Retention', icon: 'clock' },
  { to: '/admin/settings', label: 'System Settings', icon: 'sliders' },
];
