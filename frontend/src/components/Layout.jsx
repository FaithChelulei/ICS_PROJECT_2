import { useEffect, useState } from 'react';
import { NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { Avatar } from './ui.jsx';
import Icon from './Icon.jsx';

// `theme="dark"` gives the Security Auditor portal the navy "security
// operations" sidebar from the reference design; every other role keeps
// the light sidebar. Nav items can set `soon: true` for the handful of
// screens that are styled but not wired to real data yet.
//
// Phones and narrow windows (below the md breakpoint): the sidebar becomes a
// slide-in menu behind a Menu button in a top bar, so pages get the full
// width. From md upwards the layout is unchanged.
export default function Layout({ navItems, portalLabel, theme = 'light', children }) {
  const { user, logout } = useAuth();
  const dark = theme === 'dark';
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();
  useEffect(() => setMenuOpen(false), [location.pathname]);
  // Set by ProtectedRoute when this person opened a page meant for another role.
  const refused = location.state && location.state.refusedPage;
  const refusedFor = refused
    ? (refused.startsWith('/auditor') ? 'Security Auditors' : refused.startsWith('/admin') ? 'System Administrators' : refused.startsWith('/educator') ? 'Educators' : 'Caregivers')
    : null;

  return (
    <div className="min-h-screen bg-cream md:flex">
      <div className={`md:hidden sticky top-0 z-30 flex items-center justify-between px-4 py-3 border-b ${
        dark ? 'bg-navy-900 border-navy-700 text-white' : 'bg-white border-[#EFE4D0] text-ink'}`}>
        <span className="font-display text-lg font-bold">ChildGuard <span className={`text-sm font-medium ${dark ? 'text-white/50' : 'text-slate-400'}`}>{portalLabel}</span></span>
        <button type="button" aria-expanded={menuOpen} aria-label="Menu" onClick={() => setMenuOpen((o) => !o)}
          className={`rounded-lg px-3 py-1.5 text-sm font-semibold border ${dark ? 'border-white/20' : 'border-[#E4D9C6]'}`}>
          {menuOpen ? 'Close' : 'Menu'}
        </button>
      </div>
      {menuOpen && <div className="md:hidden fixed inset-0 z-30 bg-navy-900/50" onClick={() => setMenuOpen(false)} aria-hidden="true" />}
      <div
        className={`w-72 flex-col shrink-0 border-r ${menuOpen ? 'flex fixed inset-y-0 left-0 z-40 overflow-y-auto' : 'hidden'} md:static md:flex ${
          dark ? 'bg-navy-900 border-navy-700' : 'bg-white border-[#EFE4D0]'
        }`}
      >
        <div className={`px-6 py-6 border-b ${dark ? 'border-white/10' : 'border-[#F1E7D3]'}`}>
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-brand-600 flex items-center justify-center shrink-0">
              <svg width="18" height="18" viewBox="0 0 16 16" fill="none">
                <rect x="1.5" y="1.5" width="6" height="6" rx="1.5" fill="white" />
                <rect x="8.5" y="1.5" width="6" height="6" rx="1.5" fill="white" opacity="0.55" />
                <rect x="1.5" y="8.5" width="6" height="6" rx="1.5" fill="white" opacity="0.55" />
                <rect x="8.5" y="8.5" width="6" height="6" rx="1.5" fill="white" />
              </svg>
            </div>
            <span className={`font-display text-lg font-bold tracking-tight ${dark ? 'text-white' : 'text-ink'}`}>
              ChildGuard
            </span>
          </div>
          <div className={`mt-1 text-sm font-medium ${dark ? 'text-white/50' : 'text-slate-400'}`}>
            {portalLabel}
          </div>
        </div>

        <nav className="flex-1 px-3 py-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center justify-between rounded-xl px-3.5 py-2.5 text-[15px] font-medium transition ${
                  isActive
                    ? dark
                      ? 'bg-white/10 text-white'
                      : 'bg-brand-50 text-brand-700'
                    : dark
                    ? 'text-white/60 hover:bg-white/5 hover:text-white'
                    : 'text-slate-600 hover:bg-cream-100 hover:text-ink'
                }`
              }
            >
              <span className="flex items-center gap-2.5">
                {item.icon && <Icon name={item.icon} />}
                {item.label}
              </span>
              {item.soon && (
                <span
                  className={`text-[10px] font-semibold uppercase tracking-wide rounded-full px-2 py-0.5 ${
                    dark ? 'bg-white/10 text-white/60' : 'bg-slate-100 text-slate-400'
                  }`}
                >
                  Soon
                </span>
              )}
            </NavLink>
          ))}
        </nav>

        <div className={`px-4 py-4 border-t ${dark ? 'border-white/10' : 'border-[#F1E7D3]'}`}>
          <div className="flex items-center gap-2.5 px-2 mb-3">
            <Avatar
              initial={(user?.fullName || user?.email || '?')[0].toUpperCase()}
              tone={dark ? 'slate' : 'brand'}
            />
            <div className="min-w-0">
              <div className={`text-[15px] font-medium truncate ${dark ? 'text-white' : 'text-ink'}`}>
                {user?.fullName || user?.email}
              </div>
              <div className={`text-sm ${dark ? 'text-white/40' : 'text-slate-400'}`}>{user?.role}</div>
            </div>
          </div>
          <button
            onClick={logout}
            className={`w-full text-left rounded-xl px-2 py-2 text-[15px] font-medium transition ${
              dark
                ? 'text-white/50 hover:bg-white/5 hover:text-white'
                : 'text-slate-500 hover:bg-cream-100 hover:text-red-600'
            }`}
          >
            Log out
          </button>
        </div>
      </div>
      <div className="flex-1 min-w-0 overflow-auto">
        {refused && (
          <div role="alert" className="flex flex-wrap items-center justify-between gap-3 border-b border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800 md:px-8">
            <span>
              <strong>Access refused.</strong> {refused} is only for {refusedFor}, so you were brought back to your own home page.
              The server refuses that page&rsquo;s data to your role as well.
            </span>
            <button type="button" className="font-semibold underline" onClick={() => navigate(location.pathname, { replace: true, state: null })}>
              Dismiss
            </button>
          </div>
        )}
        {children}
      </div>
    </div>
  );
}
