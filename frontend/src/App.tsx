import { Routes, Route, Navigate } from 'react-router-dom';
import { useAuthStore } from './stores/authStore';
import Layout from './components/Layout';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import LogsPage from './pages/LogsPage';
import RulesPage from './pages/RulesPage';
import IncidentsPage from './pages/IncidentsPage';
import SettingsPage from './pages/SettingsPage';
import MFASetupPage from './pages/MFASetupPage';

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((state) => state.isAuthenticated);
  
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }
  
  return <>{children}</>;
}

function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        path="/"
        element={
          <ProtectedRoute>
            <Layout />
          </ProtectedRoute>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="alerts" element={<AlertsPage />} />
        <Route path="logs" element={<LogsPage />} />
        <Route path="rules" element={<RulesPage />} />
        <Route path="incidents" element={<IncidentsPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="settings/mfa" element={<MFASetupPage />} />
      </Route>
    </Routes>
  );
}

export default App;
