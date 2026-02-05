import { useQuery, useQueryClient } from '@tanstack/react-query';
import { dashboardApi, alertsApi } from '../services/api';
import { useDashboardWebSocket } from '../hooks/useWebSocket';
import {
  Bell,
  AlertTriangle,
  Shield,
  Activity,
  TrendingUp,
  TrendingDown,
  Server,
  Clock,
  Wifi,
  WifiOff,
} from 'lucide-react';
import { Line, Doughnut } from 'react-chartjs-2';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  Title,
  Tooltip,
  Legend,
  ArcElement,
  Filler,
} from 'chart.js';
import clsx from 'clsx';

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Title,
  Tooltip,
  Legend,
  Filler
);

interface StatCardProps {
  title: string;
  value: string | number;
  change?: number;
  icon: React.ElementType;
  color: 'blue' | 'red' | 'yellow' | 'green';
}

function StatCard({ title, value, change, icon: Icon, color }: StatCardProps) {
  const colorClasses = {
    blue: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
    red: 'bg-red-500/10 text-red-400 border-red-500/30',
    yellow: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/30',
    green: 'bg-green-500/10 text-green-400 border-green-500/30',
  };

  return (
    <div className="card p-6">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-dark-400">{title}</p>
          <p className="text-3xl font-bold text-dark-100 mt-1">{value}</p>
          {change !== undefined && (
            <div className="flex items-center gap-1 mt-2">
              {change >= 0 ? (
                <TrendingUp className="w-4 h-4 text-green-400" />
              ) : (
                <TrendingDown className="w-4 h-4 text-red-400" />
              )}
              <span
                className={clsx(
                  'text-sm font-medium',
                  change >= 0 ? 'text-green-400' : 'text-red-400'
                )}
              >
                {Math.abs(change)}%
              </span>
              <span className="text-dark-500 text-sm">vs last week</span>
            </div>
          )}
        </div>
        <div className={clsx('p-3 rounded-lg border', colorClasses[color])}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const classes: Record<string, string> = {
    critical: 'badge-critical',
    high: 'badge-high',
    medium: 'badge-medium',
    low: 'badge-low',
    info: 'badge-info',
  };

  return (
    <span className={classes[severity] || 'badge-info'}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}

export default function DashboardPage() {
  const queryClient = useQueryClient();
  
  // Real-time WebSocket connection
  const { isConnected } = useDashboardWebSocket({
    onNewAlert: () => {
      // Invalidate queries to fetch fresh data when new alert arrives
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
      queryClient.invalidateQueries({ queryKey: ['recent-alerts'] });
    },
    onStatsUpdate: () => {
      queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
    },
  });

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ['dashboard-stats'],
    queryFn: () => dashboardApi.getStats(),
    refetchInterval: 30000,
  });

  const { data: trends } = useQuery({
    queryKey: ['alert-trends'],
    queryFn: () => dashboardApi.getAlertTrends(7),
    refetchInterval: 60000,
  });

  const { data: recentAlerts } = useQuery({
    queryKey: ['recent-alerts'],
    queryFn: () => alertsApi.list({ limit: 5 }),
    refetchInterval: 30000,
  });

  const { data: eventDistribution } = useQuery({
    queryKey: ['event-distribution'],
    queryFn: () => dashboardApi.getEventTypeDistribution(),
    refetchInterval: 60000,
  });

  const lineChartData = {
    labels: trends?.data?.map((t: any) => t.date) || [],
    datasets: [
      {
        label: 'Critical',
        data: trends?.data?.map((t: any) => t.critical) || [],
        borderColor: '#dc2626',
        backgroundColor: 'rgba(220, 38, 38, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'High',
        data: trends?.data?.map((t: any) => t.high) || [],
        borderColor: '#ea580c',
        backgroundColor: 'rgba(234, 88, 12, 0.1)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'Medium',
        data: trends?.data?.map((t: any) => t.medium) || [],
        borderColor: '#ca8a04',
        backgroundColor: 'rgba(202, 138, 4, 0.1)',
        fill: true,
        tension: 0.4,
      },
    ],
  };

  const doughnutData = {
    labels: eventDistribution?.event_types?.map((e: any) => e.type) || [],
    datasets: [
      {
        data: eventDistribution?.event_types?.map((e: any) => e.count) || [],
        backgroundColor: [
          '#6366f1',
          '#8b5cf6',
          '#a855f7',
          '#d946ef',
          '#ec4899',
          '#f43f5e',
        ],
        borderWidth: 0,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: {
          color: '#94a3b8',
        },
      },
    },
    scales: {
      x: {
        grid: {
          color: '#334155',
        },
        ticks: {
          color: '#94a3b8',
        },
      },
      y: {
        grid: {
          color: '#334155',
        },
        ticks: {
          color: '#94a3b8',
        },
      },
    },
  };

  if (statsLoading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-primary-500" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Dashboard</h1>
          <p className="text-dark-400 mt-1">Security overview and metrics</p>
        </div>
        <div className="flex items-center gap-2">
          {isConnected ? (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-green-500/10 border border-green-500/30 rounded-full">
              <Wifi className="w-4 h-4 text-green-400" />
              <span className="text-sm text-green-400">Live</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1.5 bg-dark-700 border border-dark-600 rounded-full">
              <WifiOff className="w-4 h-4 text-dark-400" />
              <span className="text-sm text-dark-400">Offline</span>
            </div>
          )}
        </div>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Alerts"
          value={stats?.total_alerts || 0}
          change={12}
          icon={Bell}
          color="blue"
        />
        <StatCard
          title="Critical Alerts"
          value={stats?.critical_alerts || 0}
          change={-8}
          icon={AlertTriangle}
          color="red"
        />
        <StatCard
          title="Active Rules"
          value={stats?.active_rules || 0}
          icon={Shield}
          color="green"
        />
        <StatCard
          title="Events/min"
          value={stats?.events_per_minute || 0}
          change={5}
          icon={Activity}
          color="yellow"
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Alert trends */}
        <div className="lg:col-span-2 card p-6">
          <h3 className="text-lg font-semibold text-dark-100 mb-4">Alert Trends (7 days)</h3>
          <div className="h-80">
            <Line data={lineChartData} options={chartOptions} />
          </div>
        </div>

        {/* Event distribution */}
        <div className="card p-6">
          <h3 className="text-lg font-semibold text-dark-100 mb-4">Event Types</h3>
          <div className="h-80 flex items-center justify-center">
            <Doughnut
              data={doughnutData}
              options={{
                ...chartOptions,
                scales: undefined,
                cutout: '60%',
              }}
            />
          </div>
        </div>
      </div>

      {/* Recent alerts table */}
      <div className="card">
        <div className="p-4 border-b border-dark-700">
          <h3 className="text-lg font-semibold text-dark-100">Recent Alerts</h3>
        </div>
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Source</th>
                <th>Time</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts?.map((alert: any) => (
                <tr key={alert.id}>
                  <td>
                    <SeverityBadge severity={alert.severity} />
                  </td>
                  <td className="font-medium">{alert.title}</td>
                  <td className="font-mono text-sm text-dark-400">{alert.source_ip || '-'}</td>
                  <td className="text-dark-400">
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(alert.created_at).toLocaleString()}
                    </div>
                  </td>
                  <td>
                    <span
                      className={clsx(
                        'badge',
                        alert.status === 'new' && 'bg-blue-500/20 text-blue-400',
                        alert.status === 'acknowledged' && 'bg-yellow-500/20 text-yellow-400',
                        alert.status === 'resolved' && 'bg-green-500/20 text-green-400'
                      )}
                    >
                      {alert.status}
                    </span>
                  </td>
                </tr>
              ))}
              {(!recentAlerts || recentAlerts.length === 0) && (
                <tr>
                  <td colSpan={5} className="text-center py-8 text-dark-400">
                    No recent alerts
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* System status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <Server className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Elasticsearch</p>
              <p className="font-medium text-green-400">Healthy</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <Server className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">PostgreSQL</p>
              <p className="font-medium text-green-400">Healthy</p>
            </div>
          </div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10">
              <Server className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-sm text-dark-400">Redis</p>
              <p className="font-medium text-green-400">Healthy</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
