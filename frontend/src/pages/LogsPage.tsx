import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { logsApi } from '../services/api';
import { useLogsWebSocket } from '../hooks/useWebSocket';
import {
  FileText,
  Search,
  Filter,
  ChevronLeft,
  ChevronRight,
  Clock,
  RefreshCw,
  Wifi,
  WifiOff,
} from 'lucide-react';
import clsx from 'clsx';

const SOURCE_OPTIONS = ['all', 'linux_auth', 'linux_syslog', 'windows_security', 'windows_system'];
const SEVERITY_OPTIONS = ['all', 'critical', 'high', 'medium', 'low', 'info'];

export default function LogsPage() {
  const [page, setPage] = useState(1);
  const [sourceFilter, setSourceFilter] = useState('all');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const pageSize = 50;
  const queryClient = useQueryClient();

  // Real-time WebSocket connection for logs
  const { isConnected } = useLogsWebSocket(() => {
    // Refetch logs when new ones arrive
    queryClient.invalidateQueries({ queryKey: ['logs'] });
  });

  const { data, isLoading, refetch, isFetching } = useQuery({
    queryKey: ['logs', page, sourceFilter, severityFilter, searchQuery],
    queryFn: () =>
      logsApi.search({
        query: searchQuery || undefined,
        source: sourceFilter !== 'all' ? sourceFilter : undefined,
        severity: severityFilter !== 'all' ? severityFilter : undefined,
        skip: (page - 1) * pageSize,
        limit: pageSize,
      }),
    refetchInterval: 30000,
  });

  const logs = data?.data?.hits || [];
  const total = data?.data?.total || 0;
  const totalPages = Math.ceil(total / pageSize);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    setSearchQuery(searchInput);
    setPage(1);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Log Explorer</h1>
          <p className="text-dark-400 mt-1">Search and analyze security events</p>
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
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="btn-secondary"
          >
            <RefreshCw className={clsx('w-4 h-4 mr-2', isFetching && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </div>

      {/* Search and filters */}
      <div className="card p-4">
        <form onSubmit={handleSearch} className="flex flex-wrap items-center gap-4">
          <div className="relative flex-1 min-w-[300px]">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-dark-400" />
            <input
              type="text"
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
              placeholder="Search logs... (e.g., failed login, 192.168.1.1, root)"
              className="input pl-9"
            />
          </div>

          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-dark-400" />
          </div>

          <select
            value={sourceFilter}
            onChange={(e) => {
              setSourceFilter(e.target.value);
              setPage(1);
            }}
            className="input w-auto"
          >
            {SOURCE_OPTIONS.map((opt) => (
              <option key={opt} value={opt}>
                {opt === 'all'
                  ? 'All Sources'
                  : opt
                      .split('_')
                      .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
                      .join(' ')}
              </option>
            ))}
          </select>

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

          <button type="submit" className="btn-primary">
            Search
          </button>
        </form>
      </div>

      {/* Results info */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-dark-400">
          Found <span className="font-medium text-dark-200">{total.toLocaleString()}</span> events
        </p>
      </div>

      {/* Logs list */}
      <div className="space-y-2">
        {isLoading ? (
          <div className="card p-12 flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500" />
          </div>
        ) : logs.length === 0 ? (
          <div className="card p-12 text-center text-dark-400">
            <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No logs found matching your criteria</p>
          </div>
        ) : (
          logs.map((log: any, index: number) => (
            <div key={log._id || index} className="card p-4 hover:border-dark-600 transition-colors">
              <div className="flex items-start gap-4">
                <div className="flex-shrink-0">
                  <span
                    className={clsx(
                      'inline-flex items-center px-2 py-1 rounded text-xs font-medium',
                      log._source?.severity === 'critical' && 'bg-red-500/20 text-red-400',
                      log._source?.severity === 'high' && 'bg-orange-500/20 text-orange-400',
                      log._source?.severity === 'medium' && 'bg-yellow-500/20 text-yellow-400',
                      log._source?.severity === 'low' && 'bg-green-500/20 text-green-400',
                      (!log._source?.severity || log._source?.severity === 'info') &&
                        'bg-blue-500/20 text-blue-400'
                    )}
                  >
                    {(log._source?.severity || 'info').toUpperCase()}
                  </span>
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-xs font-medium text-primary-400">
                      {log._source?.source || 'unknown'}
                    </span>
                    <span className="text-dark-600">|</span>
                    <span className="text-xs text-dark-400">{log._source?.host || '-'}</span>
                    <span className="text-dark-600">|</span>
                    <span className="text-xs text-dark-400 flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {log._source?.timestamp
                        ? new Date(log._source.timestamp).toLocaleString()
                        : '-'}
                    </span>
                  </div>

                  <p className="font-mono text-sm text-dark-200 break-all">
                    {log._source?.message || JSON.stringify(log._source)}
                  </p>

                  {log._source?.parsed && (
                    <div className="mt-2 flex flex-wrap gap-2">
                      {Object.entries(log._source.parsed)
                        .slice(0, 5)
                        .map(([key, value]) => (
                          <span
                            key={key}
                            className="inline-flex items-center px-2 py-0.5 rounded bg-dark-700 text-xs"
                          >
                            <span className="text-dark-400">{key}:</span>
                            <span className="text-dark-200 ml-1">{String(value)}</span>
                          </span>
                        ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between">
          <p className="text-sm text-dark-400">
            Showing {(page - 1) * pageSize + 1} to {Math.min(page * pageSize, total)} of {total}{' '}
            results
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
  );
}
