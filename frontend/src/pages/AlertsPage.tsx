import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { alertsApi } from '../services/api';
import { useAlertsWebSocket } from '../hooks/useWebSocket';
import {
  Bell,
  Filter,
  Search,
  ChevronLeft,
  ChevronRight,
  Check,
  Clock,
  ExternalLink,
  Wifi,
  WifiOff,
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';

const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'];
const STATUS_OPTIONS = ['all', 'new', 'acknowledged', 'in_progress', 'resolved', 'false_positive'];

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

export default function AlertsPage() {
  const [page, setPage] = useState(1);
  const [severityFilter, setSeverityFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [search, setSearch] = useState('');
  const pageSize = 20;
  const queryClient = useQueryClient();

  // Real-time WebSocket connection
  const { isConnected } = useAlertsWebSocket((newAlert) => {
    // Refetch alerts when a new one arrives
    queryClient.invalidateQueries({ queryKey: ['alerts'] });
    // Show toast notification for new alerts
    if (newAlert?.title) {
      toast(`New Alert: ${newAlert.title}`, { icon: '🚨' });
    }
  });

  const { data, isLoading } = useQuery({
    queryKey: ['alerts', page, severityFilter, statusFilter, search],
    queryFn: () =>
      alertsApi.list({
        skip: (page - 1) * pageSize,
        limit: pageSize,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        status: statusFilter !== 'all' ? statusFilter : undefined,
      }),
    refetchInterval: 30000,
  });

  const acknowledgeMutation = useMutation({
    mutationFn: (id: string) => alertsApi.acknowledge(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      toast.success('Alert acknowledged');
    },
    onError: () => {
      toast.error('Failed to acknowledge alert');
    },
  });

  const responseData = data?.data;
  const alerts = responseData?.items || responseData?.data || responseData || [];
  const total = responseData?.total || (Array.isArray(responseData) ? responseData.length : 0);
  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Alerts</h1>
          <p className="text-dark-400 mt-1">Monitor and manage security alerts</p>
        </div>
        <div className="flex items-center gap-3">
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
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-red-500/10 border border-red-500/20">
            <Bell className="w-4 h-4 text-red-400" />
            <span className="text-sm font-medium text-red-400">
              {total} Total Alerts
            </span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-4">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-dark-400" />
            <span className="text-sm text-dark-400">Filters:</span>
          </div>

          <div className="relative flex-1 max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search alerts..."
              className="input pl-9"
            />
          </div>

          <select
            value={severityFilter}
            onChange={(e) => {
              setSeverityFilter(e.target.value);
              setPage(1);
            }}
            className="input w-auto"
          >
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === 'all' ? 'All Severities' : opt.charAt(0).toUpperCase() + opt.slice(1)}
              </option>
            ))}
          </select>

          <select
            value={statusFilter}
            onChange={(e) => {
              setStatusFilter(e.target.value);
              setPage(1);
            }}
            className="input w-auto"
          >
            {STATUS_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === 'all'
                  ? 'All Statuses'
                  : opt
                      .split('_')
                      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                      .join(' ')}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Alerts table */}
      <div className="card">
        <div className="table-container">
          <table className="table">
            <thead>
              <tr>
                <th>Severity</th>
                <th>Title</th>
                <th>Rule</th>
                <th>Source</th>
                <th>Time</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="text-center py-12">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500 mx-auto" />
                  </td>
                </tr>
              ) : alerts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="text-center py-12 text-dark-400">
                    No alerts found
                  </td>
                </tr>
              ) : (
                alerts.map((alert: any) => (
                  <tr key={alert.id}>
                    <td>
                      <SeverityBadge severity={alert.severity} />
                    </td>
                    <td>
                      <div>
                        <p className="font-medium text-dark-100">{alert.title}</p>
                        <p className="text-sm text-dark-400 truncate max-w-md">
                          {alert.description}
                        </p>
                      </div>
                    </td>
                    <td className="text-dark-300">{alert.rule_name || '-'}</td>
                    <td className="font-mono text-sm text-dark-400">
                      {alert.source_ip || '-'}
                    </td>
                    <td className="text-dark-400 whitespace-nowrap">
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
                          alert.status === 'in_progress' && 'bg-purple-500/20 text-purple-400',
                          alert.status === 'resolved' && 'bg-green-500/20 text-green-400',
                          alert.status === 'false_positive' && 'bg-gray-500/20 text-gray-400'
                        )}
                      >
                        {alert.status.replace('_', ' ')}
                      </span>
                    </td>
                    <td>
                      <div className="flex items-center gap-2">
                        {alert.status === 'new' && (
                          <button
                            onClick={() => acknowledgeMutation.mutate(alert.id)}
                            disabled={acknowledgeMutation.isPending}
                            className="btn-ghost p-1.5"
                            title="Acknowledge"
                          >
                            <Check className="w-4 h-4" />
                          </button>
                        )}
                        <button className="btn-ghost p-1.5" title="View Details">
                          <ExternalLink className="w-4 h-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between p-4 border-t border-dark-700">
            <p className="text-sm text-dark-400">
              Showing {(page - 1) * pageSize + 1} to{' '}
              {Math.min(page * pageSize, total)} of {total} results
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="btn-secondary p-2"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <span className="text-sm text-dark-300">
                Page {page} of {totalPages}
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="btn-secondary p-2"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
