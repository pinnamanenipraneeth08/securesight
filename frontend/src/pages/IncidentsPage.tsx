import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { incidentsApi } from '../services/api';
import {
  AlertTriangle,
  Plus,
  Clock,
  User,
  ChevronRight,
  MessageSquare,
  FileText,
} from 'lucide-react';
import clsx from 'clsx';

const STATUS_OPTIONS = ['all', 'open', 'investigating', 'contained', 'resolved', 'closed'];
const PRIORITY_COLORS: Record<string, string> = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-500',
  medium: 'border-l-yellow-500',
  low: 'border-l-green-500',
};

interface Incident {
  id: string;
  title: string;
  description: string;
  status: string;
  priority: string;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  timeline: any[];
  affected_assets: string[];
}

export default function IncidentsPage() {
  const [statusFilter, setStatusFilter] = useState('all');
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);

  const { data, isLoading } = useQuery({
    queryKey: ['incidents', statusFilter],
    queryFn: () =>
      incidentsApi.list({
        status: statusFilter !== 'all' ? statusFilter : undefined,
      }),
  });

  const incidents: Incident[] = data?.data || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Incidents</h1>
          <p className="text-dark-400 mt-1">Track and manage security incidents</p>
        </div>
        <button onClick={() => setShowCreateModal(true)} className="btn-primary">
          <Plus className="w-4 h-4 mr-2" />
          Create Incident
        </button>
      </div>

      {/* Status filters */}
      <div className="card p-4">
        <div className="flex flex-wrap items-center gap-2">
          {STATUS_OPTIONS.map((status) => (
            <button
              key={status}
              onClick={() => setStatusFilter(status)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-sm font-medium transition-colors',
                statusFilter === status
                  ? 'bg-primary-600/20 text-primary-400 border border-primary-500/30'
                  : 'text-dark-400 hover:bg-dark-700'
              )}
            >
              {status === 'all'
                ? 'All'
                : status.charAt(0).toUpperCase() + status.slice(1)}
            </button>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Incidents list */}
        <div className="lg:col-span-2 space-y-3">
          {isLoading ? (
            <div className="card p-12 flex items-center justify-center">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500" />
            </div>
          ) : incidents.length === 0 ? (
            <div className="card p-12 text-center text-dark-400">
              <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No incidents found</p>
            </div>
          ) : (
            incidents.map((incident) => (
              <div
                key={incident.id}
                onClick={() => setSelectedIncident(incident)}
                className={clsx(
                  'card p-4 cursor-pointer border-l-4 hover:bg-dark-700/30 transition-colors',
                  PRIORITY_COLORS[incident.priority] || 'border-l-dark-600',
                  selectedIncident?.id === incident.id && 'ring-1 ring-primary-500'
                )}
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <h3 className="font-medium text-dark-100 truncate">{incident.title}</h3>
                      <span
                        className={clsx(
                          'badge',
                          incident.status === 'open' && 'bg-red-500/20 text-red-400',
                          incident.status === 'investigating' && 'bg-yellow-500/20 text-yellow-400',
                          incident.status === 'contained' && 'bg-blue-500/20 text-blue-400',
                          incident.status === 'resolved' && 'bg-green-500/20 text-green-400',
                          incident.status === 'closed' && 'bg-dark-600 text-dark-400'
                        )}
                      >
                        {incident.status}
                      </span>
                    </div>
                    <p className="text-sm text-dark-400 line-clamp-2">{incident.description}</p>
                    <div className="flex items-center gap-4 mt-2 text-xs text-dark-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3 h-3" />
                        {new Date(incident.created_at).toLocaleDateString()}
                      </span>
                      {incident.assigned_to && (
                        <span className="flex items-center gap-1">
                          <User className="w-3 h-3" />
                          {incident.assigned_to}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <MessageSquare className="w-3 h-3" />
                        {incident.timeline?.length || 0} updates
                      </span>
                    </div>
                  </div>
                  <ChevronRight className="w-5 h-5 text-dark-500 flex-shrink-0" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Incident details panel */}
        <div className="card h-fit sticky top-20">
          {selectedIncident ? (
            <>
              <div className="p-4 border-b border-dark-700">
                <h2 className="font-semibold text-dark-100">{selectedIncident.title}</h2>
                <div className="flex items-center gap-2 mt-2">
                  <span
                    className={clsx(
                      'badge',
                      selectedIncident.priority === 'critical' && 'badge-critical',
                      selectedIncident.priority === 'high' && 'badge-high',
                      selectedIncident.priority === 'medium' && 'badge-medium',
                      selectedIncident.priority === 'low' && 'badge-low'
                    )}
                  >
                    {selectedIncident.priority} priority
                  </span>
                </div>
              </div>

              <div className="p-4 space-y-4">
                <div>
                  <h4 className="text-xs font-medium text-dark-400 uppercase mb-1">Description</h4>
                  <p className="text-sm text-dark-200">{selectedIncident.description}</p>
                </div>

                <div>
                  <h4 className="text-xs font-medium text-dark-400 uppercase mb-1">Status</h4>
                  <select
                    className="input"
                    value={selectedIncident.status}
                    onChange={() => {
                      // TODO: Update status
                    }}
                  >
                    {STATUS_OPTIONS.filter((s) => s !== 'all').map((status) => (
                      <option key={status} value={status}>
                        {status.charAt(0).toUpperCase() + status.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>

                {selectedIncident.affected_assets?.length > 0 && (
                  <div>
                    <h4 className="text-xs font-medium text-dark-400 uppercase mb-1">
                      Affected Assets
                    </h4>
                    <div className="flex flex-wrap gap-1">
                      {selectedIncident.affected_assets.map((asset) => (
                        <span key={asset} className="badge bg-dark-700 text-dark-300">
                          {asset}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                <div>
                  <h4 className="text-xs font-medium text-dark-400 uppercase mb-2">Timeline</h4>
                  <div className="space-y-3 max-h-60 overflow-y-auto">
                    {selectedIncident.timeline?.length > 0 ? (
                      selectedIncident.timeline.map((entry: any, i: number) => (
                        <div key={i} className="flex gap-3">
                          <div className="w-2 h-2 rounded-full bg-primary-500 mt-2 flex-shrink-0" />
                          <div className="flex-1 min-w-0">
                            <p className="text-sm text-dark-200">{entry.message}</p>
                            <p className="text-xs text-dark-500 mt-0.5">
                              {new Date(entry.timestamp).toLocaleString()}
                            </p>
                          </div>
                        </div>
                      ))
                    ) : (
                      <p className="text-sm text-dark-500">No timeline entries yet</p>
                    )}
                  </div>
                </div>

                <div className="pt-4 border-t border-dark-700">
                  <textarea
                    className="input mb-2"
                    rows={2}
                    placeholder="Add timeline update..."
                  />
                  <button className="btn-primary w-full text-sm">Add Update</button>
                </div>
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-dark-400">
              <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>Select an incident to view details</p>
            </div>
          )}
        </div>
      </div>

      {/* Create Incident Modal placeholder */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="card w-full max-w-lg">
            <div className="p-4 border-b border-dark-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Create Incident</h2>
              <button onClick={() => setShowCreateModal(false)} className="btn-ghost p-1">
                ×
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">Title</label>
                <input type="text" className="input" placeholder="Incident title..." />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">Description</label>
                <textarea className="input" rows={4} placeholder="Describe the incident..." />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">Priority</label>
                <select className="input">
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                </select>
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button onClick={() => setShowCreateModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button className="btn-primary">Create</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
