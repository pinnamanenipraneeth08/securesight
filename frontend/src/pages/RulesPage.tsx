import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { rulesApi } from '../services/api';
import {
  Shield,
  Plus,
  Edit2,
  Trash2,
  ToggleLeft,
  ToggleRight,
  ChevronDown,
  ChevronUp,
  Play,
} from 'lucide-react';
import clsx from 'clsx';
import toast from 'react-hot-toast';

const RULE_TYPES = ['threshold', 'correlation', 'signature', 'anomaly'];
const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

interface Rule {
  id: string;
  name: string;
  description: string;
  rule_type: string;
  severity: string;
  enabled: boolean;
  conditions: any;
  mitre_tactics: string[];
  mitre_techniques: string[];
  created_at: string;
}

export default function RulesPage() {
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [filterEnabled, setFilterEnabled] = useState<boolean | undefined>(undefined);
  const queryClient = useQueryClient();

  const { data, isLoading } = useQuery({
    queryKey: ['rules', filterEnabled],
    queryFn: () => rulesApi.list({ enabled: filterEnabled }),
  });

  const toggleMutation = useMutation({
    mutationFn: (id: string) => rulesApi.toggle(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      toast.success('Rule toggled');
    },
    onError: () => {
      toast.error('Failed to toggle rule');
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => rulesApi.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['rules'] });
      toast.success('Rule deleted');
    },
    onError: () => {
      toast.error('Failed to delete rule');
    },
  });

  const rules: Rule[] = data?.data || [];

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Detection Rules</h1>
          <p className="text-dark-400 mt-1">Manage threat detection rules</p>
        </div>
        <button onClick={() => setShowCreateModal(true)} className="btn-primary">
          <Plus className="w-4 h-4 mr-2" />
          Create Rule
        </button>
      </div>

      {/* Filters */}
      <div className="card p-4">
        <div className="flex items-center gap-4">
          <span className="text-sm text-dark-400">Filter:</span>
          <button
            onClick={() => setFilterEnabled(undefined)}
            className={clsx(
              'btn-ghost px-3 py-1.5 text-sm',
              filterEnabled === undefined && 'bg-primary-600/20 text-primary-400'
            )}
          >
            All
          </button>
          <button
            onClick={() => setFilterEnabled(true)}
            className={clsx(
              'btn-ghost px-3 py-1.5 text-sm',
              filterEnabled === true && 'bg-green-600/20 text-green-400'
            )}
          >
            Enabled
          </button>
          <button
            onClick={() => setFilterEnabled(false)}
            className={clsx(
              'btn-ghost px-3 py-1.5 text-sm',
              filterEnabled === false && 'bg-red-600/20 text-red-400'
            )}
          >
            Disabled
          </button>
        </div>
      </div>

      {/* Rules list */}
      <div className="space-y-3">
        {isLoading ? (
          <div className="card p-12 flex items-center justify-center">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500" />
          </div>
        ) : rules.length === 0 ? (
          <div className="card p-12 text-center text-dark-400">
            <Shield className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p>No rules found</p>
          </div>
        ) : (
          rules.map((rule) => (
            <div key={rule.id} className="card">
              <div
                className="p-4 cursor-pointer hover:bg-dark-700/30 transition-colors"
                onClick={() => setExpandedRule(expandedRule === rule.id ? null : rule.id)}
              >
                <div className="flex items-center gap-4">
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      toggleMutation.mutate(rule.id);
                    }}
                    className={clsx(
                      'flex-shrink-0',
                      rule.enabled ? 'text-green-400' : 'text-dark-500'
                    )}
                  >
                    {rule.enabled ? (
                      <ToggleRight className="w-6 h-6" />
                    ) : (
                      <ToggleLeft className="w-6 h-6" />
                    )}
                  </button>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <h3 className="font-medium text-dark-100">{rule.name}</h3>
                      <span
                        className={clsx(
                          'badge',
                          rule.severity === 'critical' && 'badge-critical',
                          rule.severity === 'high' && 'badge-high',
                          rule.severity === 'medium' && 'badge-medium',
                          rule.severity === 'low' && 'badge-low',
                          rule.severity === 'info' && 'badge-info'
                        )}
                      >
                        {rule.severity}
                      </span>
                      <span className="badge bg-dark-700 text-dark-300">{rule.rule_type}</span>
                    </div>
                    <p className="text-sm text-dark-400 mt-1 truncate">{rule.description}</p>
                  </div>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        // TODO: Open edit modal
                      }}
                      className="btn-ghost p-2"
                      title="Edit"
                    >
                      <Edit2 className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        // TODO: Test rule
                      }}
                      className="btn-ghost p-2"
                      title="Test Rule"
                    >
                      <Play className="w-4 h-4" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        if (confirm('Are you sure you want to delete this rule?')) {
                          deleteMutation.mutate(rule.id);
                        }
                      }}
                      className="btn-ghost p-2 text-red-400 hover:text-red-300"
                      title="Delete"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                    {expandedRule === rule.id ? (
                      <ChevronUp className="w-5 h-5 text-dark-400" />
                    ) : (
                      <ChevronDown className="w-5 h-5 text-dark-400" />
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded details */}
              {expandedRule === rule.id && (
                <div className="px-4 pb-4 border-t border-dark-700 pt-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <h4 className="text-sm font-medium text-dark-400 mb-2">Conditions</h4>
                      <pre className="p-3 rounded-lg bg-dark-900 text-sm font-mono text-dark-200 overflow-x-auto">
                        {JSON.stringify(rule.conditions, null, 2)}
                      </pre>
                    </div>
                    <div>
                      <h4 className="text-sm font-medium text-dark-400 mb-2">MITRE ATT&CK</h4>
                      <div className="space-y-2">
                        {rule.mitre_tactics?.length > 0 && (
                          <div>
                            <span className="text-xs text-dark-500">Tactics:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {rule.mitre_tactics.map((t) => (
                                <span key={t} className="badge bg-purple-500/20 text-purple-400">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                        {rule.mitre_techniques?.length > 0 && (
                          <div>
                            <span className="text-xs text-dark-500">Techniques:</span>
                            <div className="flex flex-wrap gap-1 mt-1">
                              {rule.mitre_techniques.map((t) => (
                                <span key={t} className="badge bg-blue-500/20 text-blue-400">
                                  {t}
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                      <div className="mt-4">
                        <span className="text-xs text-dark-500">Created:</span>
                        <p className="text-sm text-dark-300">
                          {new Date(rule.created_at).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Create Rule Modal placeholder */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="card w-full max-w-2xl max-h-[90vh] overflow-y-auto">
            <div className="p-4 border-b border-dark-700 flex items-center justify-between">
              <h2 className="text-lg font-semibold">Create Detection Rule</h2>
              <button
                onClick={() => setShowCreateModal(false)}
                className="btn-ghost p-1"
              >
                ×
              </button>
            </div>
            <div className="p-4 space-y-4">
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">Rule Name</label>
                <input type="text" className="input" placeholder="e.g., Brute Force Detection" />
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">Description</label>
                <textarea className="input" rows={3} placeholder="Describe what this rule detects..." />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Rule Type</label>
                  <select className="input">
                    {RULE_TYPES.map((type) => (
                      <option key={type} value={type}>
                        {type.charAt(0).toUpperCase() + type.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Severity</label>
                  <select className="input">
                    {SEVERITIES.map((sev) => (
                      <option key={sev} value={sev}>
                        {sev.charAt(0).toUpperCase() + sev.slice(1)}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-dark-300 mb-1">
                  Conditions (JSON)
                </label>
                <textarea
                  className="input font-mono text-sm"
                  rows={8}
                  placeholder='{"field": "event_type", "operator": "equals", "value": "auth_failure"}'
                />
              </div>
              <div className="flex justify-end gap-2 pt-4">
                <button onClick={() => setShowCreateModal(false)} className="btn-secondary">
                  Cancel
                </button>
                <button className="btn-primary">Create Rule</button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
