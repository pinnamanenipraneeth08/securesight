import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import {
  LayoutDashboard,
  Bell,
  FileText,
  Shield,
  AlertTriangle,
  Settings,
  LogOut,
  Menu,
  X,
  User,
} from 'lucide-react';
import { useState } from 'react';
import clsx from 'clsx';

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: LayoutDashboard },
  { name: 'Alerts', href: '/alerts', icon: Bell },
  { name: 'Logs', href: '/logs', icon: FileText },
  { name: 'Rules', href: '/rules', icon: Shield },
  { name: 'Incidents', href: '/incidents', icon: AlertTriangle },
  { name: 'Settings', href: '/settings', icon: Settings },
];

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { user, logout } = useAuthStore();
  const location = useLocation();

  return (
    <div className="min-h-screen bg-dark-900">
      {/* Mobile sidebar overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 lg:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={clsx(
          'fixed inset-y-0 left-0 z-50 w-64 bg-dark-800 border-r border-dark-700 transform transition-transform duration-200 ease-in-out lg:translate-x-0',
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        )}
      >
        {/* Logo */}
        <div className="flex items-center justify-between h-16 px-4 border-b border-dark-700">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary-500" />
            <span className="text-xl font-bold text-gradient">SecureSight</span>
          </div>
          <button
            className="lg:hidden p-1 rounded hover:bg-dark-700"
            onClick={() => setSidebarOpen(false)}
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 px-3 py-4 space-y-1">
          {navigation.map((item) => {
            const isActive = location.pathname === item.href;
            return (
              <NavLink
                key={item.name}
                to={item.href}
                className={clsx(
                  'flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  isActive
                    ? 'bg-primary-600/20 text-primary-400 border border-primary-500/30'
                    : 'text-dark-300 hover:bg-dark-700 hover:text-dark-100'
                )}
                onClick={() => setSidebarOpen(false)}
              >
                <item.icon className="w-5 h-5" />
                {item.name}
              </NavLink>
            );
          })}
        </nav>

        {/* User section */}
        <div className="p-4 border-t border-dark-700">
          <div className="flex items-center gap-3 mb-3">
            <div className="flex items-center justify-center w-10 h-10 rounded-full bg-primary-600/20 text-primary-400">
              <User className="w-5 h-5" />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-dark-100 truncate">
                {user?.full_name || user?.email}
              </p>
              <p className="text-xs text-dark-400 capitalize">{user?.role}</p>
            </div>
          </div>
          <button
            onClick={logout}
            className="flex items-center gap-2 w-full px-3 py-2 text-sm text-dark-400 hover:text-dark-100 hover:bg-dark-700 rounded-lg transition-colors"
          >
            <LogOut className="w-4 h-4" />
            Sign out
          </button>
        </div>
      </aside>

      {/* Main content */}
      <div className="lg:pl-64">
        {/* Top bar */}
        <header className="sticky top-0 z-30 flex items-center h-16 px-4 bg-dark-800/80 backdrop-blur border-b border-dark-700 lg:px-6">
          <button
            className="lg:hidden p-2 -ml-2 rounded-lg hover:bg-dark-700"
            onClick={() => setSidebarOpen(true)}
          >
            <Menu className="w-5 h-5" />
          </button>

          <div className="flex-1" />

          {/* Status indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-green-500/10 border border-green-500/20">
            <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse" />
            <span className="text-xs font-medium text-green-400">System Online</span>
          </div>
        </header>

        {/* Page content */}
        <main className="p-4 lg:p-6">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
