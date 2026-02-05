import { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-hot-toast';
import { healthApi, usersApi, apiKeysApi } from '../services/api';
import { useAuthStore } from '../stores/authStore';
import {
  User,
  Bell,
  Shield,
  Database,
  Key,
  Mail,
  MessageSquare,
  Send,
  CheckCircle,
  XCircle,
  RefreshCw,
  Smartphone,
  Loader2,
  Copy,
  Trash2,
  Eye,
  EyeOff,
  Plus,
  X,
} from 'lucide-react';
import clsx from 'clsx';

const TABS = [
  { id: 'profile', label: 'Profile', icon: User },
  { id: 'notifications', label: 'Notifications', icon: Bell },
  { id: 'security', label: 'Security', icon: Shield },
  { id: 'integrations', label: 'Integrations', icon: MessageSquare },
  { id: 'system', label: 'System', icon: Database },
];

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState('profile');
  const { user, setUser } = useAuthStore();
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // Profile form state
  const [fullName, setFullName] = useState(user?.full_name || '');
  const [email, setEmail] = useState(user?.email || '');

  // Password form state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');

  // API Key state
  const [showCreateKeyModal, setShowCreateKeyModal] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyDescription, setNewKeyDescription] = useState('');
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [revealedKeyId, setRevealedKeyId] = useState<string | null>(null);

  const { data: healthData, isLoading: healthLoading, refetch: refetchHealth } = useQuery({
    queryKey: ['health-detailed'],
    queryFn: () => healthApi.detailed(),
    enabled: activeTab === 'system',
  });

  // API Keys query
  const { data: apiKeys = [], isLoading: apiKeysLoading } = useQuery({
    queryKey: ['api-keys'],
    queryFn: () => apiKeysApi.list(),
    enabled: activeTab === 'security',
  });

  // Create API Key mutation
  const createApiKeyMutation = useMutation({
    mutationFn: (data: { name: string; description?: string }) => apiKeysApi.create(data),
    onSuccess: (data) => {
      setCreatedKey(data.key);
      setNewKeyName('');
      setNewKeyDescription('');
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      toast.success('API key created successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to create API key');
    },
  });

  // Delete API Key mutation
  const deleteApiKeyMutation = useMutation({
    mutationFn: (keyId: string) => apiKeysApi.delete(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      toast.success('API key deleted');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to delete API key');
    },
  });

  // Revoke API Key mutation
  const revokeApiKeyMutation = useMutation({
    mutationFn: (keyId: string) => apiKeysApi.revoke(keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['api-keys'] });
      toast.success('API key revoked');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to revoke API key');
    },
  });

  // Profile update mutation
  const updateProfileMutation = useMutation({
    mutationFn: (data: { full_name?: string; email?: string }) => usersApi.updateProfile(data),
    onSuccess: (data) => {
      setUser({ ...user!, full_name: data.full_name, email: data.email });
      toast.success('Profile updated successfully');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to update profile');
    },
  });

  // Password change mutation
  const changePasswordMutation = useMutation({
    mutationFn: (data: { current_password: string; new_password: string }) =>
      usersApi.changePassword(data),
    onSuccess: () => {
      toast.success('Password changed successfully');
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    },
    onError: (error: any) => {
      toast.error(error.response?.data?.detail || 'Failed to change password');
    },
  });

  const handleSaveProfile = () => {
    updateProfileMutation.mutate({ full_name: fullName, email });
  };

  const handleChangePassword = () => {
    if (newPassword !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }
    if (newPassword.length < 8) {
      toast.error('Password must be at least 8 characters');
      return;
    }
    changePasswordMutation.mutate({
      current_password: currentPassword,
      new_password: newPassword,
    });
  };

  const handleCreateApiKey = () => {
    if (!newKeyName.trim()) {
      toast.error('Please enter a name for the API key');
      return;
    }
    createApiKeyMutation.mutate({
      name: newKeyName.trim(),
      description: newKeyDescription.trim() || undefined,
    });
  };

  const handleCopyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    toast.success('API key copied to clipboard');
  };

  const handleCloseCreateModal = () => {
    setShowCreateKeyModal(false);
    setCreatedKey(null);
    setNewKeyName('');
    setNewKeyDescription('');
  };

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-dark-100">Settings</h1>
        <p className="text-dark-400 mt-1">Manage your account and system configuration</p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <div className="w-full lg:w-64 flex-shrink-0">
          <nav className="card p-2 space-y-1">
            {TABS.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={clsx(
                  'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                  activeTab === tab.id
                    ? 'bg-primary-600/20 text-primary-400'
                    : 'text-dark-400 hover:bg-dark-700'
                )}
              >
                <tab.icon className="w-4 h-4" />
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          {/* Profile Tab */}
          {activeTab === 'profile' && (
            <div className="card p-6 space-y-6">
              <div>
                <h2 className="text-lg font-semibold text-dark-100 mb-4">Profile Settings</h2>
                <div className="flex items-center gap-4 mb-6">
                  <div className="w-16 h-16 rounded-full bg-primary-600/20 flex items-center justify-center">
                    <User className="w-8 h-8 text-primary-400" />
                  </div>
                  <div>
                    <p className="font-medium text-dark-100">{user?.full_name || 'User'}</p>
                    <p className="text-sm text-dark-400">{user?.email}</p>
                    <p className="text-xs text-dark-500 capitalize mt-1">{user?.role} Account</p>
                  </div>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Full Name</label>
                  <input
                    type="text"
                    className="input"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Your name"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Email</label>
                  <input
                    type="email"
                    className="input"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="your@email.com"
                  />
                </div>
                <div className="pt-4">
                  <button
                    onClick={handleSaveProfile}
                    disabled={updateProfileMutation.isPending}
                    className="btn-primary flex items-center gap-2"
                  >
                    {updateProfileMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                    Save Changes
                  </button>
                </div>
              </div>
            </div>
          )}

          {/* Notifications Tab */}
          {activeTab === 'notifications' && (
            <div className="card p-6 space-y-6">
              <h2 className="text-lg font-semibold text-dark-100">Notification Preferences</h2>

              <div className="space-y-4">
                <div className="flex items-center justify-between p-4 bg-dark-700/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Mail className="w-5 h-5 text-dark-400" />
                    <div>
                      <p className="font-medium text-dark-100">Email Notifications</p>
                      <p className="text-sm text-dark-400">Receive alerts via email</p>
                    </div>
                  </div>
                  <input type="checkbox" className="w-5 h-5 accent-primary-500" defaultChecked />
                </div>

                <div className="flex items-center justify-between p-4 bg-dark-700/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    <MessageSquare className="w-5 h-5 text-dark-400" />
                    <div>
                      <p className="font-medium text-dark-100">Slack Notifications</p>
                      <p className="text-sm text-dark-400">Send alerts to Slack channel</p>
                    </div>
                  </div>
                  <input type="checkbox" className="w-5 h-5 accent-primary-500" />
                </div>

                <div className="flex items-center justify-between p-4 bg-dark-700/30 rounded-lg">
                  <div className="flex items-center gap-3">
                    <Send className="w-5 h-5 text-dark-400" />
                    <div>
                      <p className="font-medium text-dark-100">Telegram Notifications</p>
                      <p className="text-sm text-dark-400">Send alerts via Telegram bot</p>
                    </div>
                  </div>
                  <input type="checkbox" className="w-5 h-5 accent-primary-500" />
                </div>
              </div>

              <div>
                <h3 className="text-sm font-medium text-dark-300 mb-2">Alert Severity Filter</h3>
                <div className="flex flex-wrap gap-2">
                  {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                    <label key={sev} className="flex items-center gap-2 px-3 py-1.5 bg-dark-700/50 rounded-lg cursor-pointer hover:bg-dark-700">
                      <input type="checkbox" className="accent-primary-500" defaultChecked={sev === 'critical' || sev === 'high'} />
                      <span className="text-sm text-dark-200 capitalize">{sev}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="pt-4">
                <button
                  onClick={() => toast.success('Preferences saved (demo)')}
                  className="btn-primary"
                >
                  Save Preferences
                </button>
              </div>
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="space-y-6">
              {/* MFA Section */}
              <div className="card p-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary-600/20">
                      <Smartphone className="w-5 h-5 text-primary-400" />
                    </div>
                    <div>
                      <h2 className="text-lg font-semibold text-dark-100">Two-Factor Authentication</h2>
                      <p className="text-sm text-dark-400">Add an extra layer of security with an authenticator app</p>
                    </div>
                  </div>
                  <button
                    onClick={() => navigate('/settings/mfa')}
                    className="btn-primary"
                  >
                    Configure
                  </button>
                </div>
              </div>

              <div className="card p-6 space-y-4">
                <h2 className="text-lg font-semibold text-dark-100">Change Password</h2>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Current Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="••••••••"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">New Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="••••••••"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-dark-300 mb-1">Confirm New Password</label>
                  <input
                    type="password"
                    className="input"
                    placeholder="••••••••"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                  />
                </div>
                <div className="pt-2">
                  <button
                    onClick={handleChangePassword}
                    disabled={changePasswordMutation.isPending || !currentPassword || !newPassword || !confirmPassword}
                    className="btn-primary flex items-center gap-2"
                  >
                    {changePasswordMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                    Update Password
                  </button>
                </div>
              </div>

              <div className="card p-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h2 className="text-lg font-semibold text-dark-100">API Keys</h2>
                    <p className="text-sm text-dark-400">Manage API keys for agent authentication</p>
                  </div>
                  <button
                    onClick={() => setShowCreateKeyModal(true)}
                    className="btn-primary text-sm flex items-center gap-2"
                  >
                    <Plus className="w-4 h-4" />
                    Generate New Key
                  </button>
                </div>
                
                {apiKeysLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <Loader2 className="w-6 h-6 animate-spin text-dark-400" />
                  </div>
                ) : apiKeys.length === 0 ? (
                  <div className="text-center py-8 text-dark-400">
                    <Key className="w-12 h-12 mx-auto mb-3 opacity-50" />
                    <p>No API keys yet</p>
                    <p className="text-sm">Generate a key to authenticate your agents</p>
                  </div>
                ) : (
                  <div className="space-y-3">
                    {apiKeys.map((apiKey: any) => (
                      <div key={apiKey.id} className="p-4 bg-dark-700/30 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <Key className={clsx(
                              "w-5 h-5",
                              apiKey.is_active ? "text-primary-400" : "text-dark-500"
                            )} />
                            <div>
                              <p className="font-medium text-dark-200">{apiKey.name}</p>
                              <div className="flex items-center gap-2 mt-1">
                                <code className="font-mono text-sm text-dark-400">
                                  {revealedKeyId === apiKey.id ? apiKey.key_prefix + '...' : apiKey.key_prefix + '••••••••'}
                                </code>
                                {!apiKey.is_active && (
                                  <span className="badge bg-red-600/20 text-red-400 text-xs">Revoked</span>
                                )}
                              </div>
                              <p className="text-xs text-dark-500 mt-1">
                                Created: {formatDate(apiKey.created_at)}
                                {apiKey.last_used_at && ` • Last used: ${formatDate(apiKey.last_used_at)}`}
                              </p>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => setRevealedKeyId(revealedKeyId === apiKey.id ? null : apiKey.id)}
                              className="btn-ghost text-sm p-2"
                              title={revealedKeyId === apiKey.id ? "Hide" : "Reveal prefix"}
                            >
                              {revealedKeyId === apiKey.id ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                            </button>
                            {apiKey.is_active && (
                              <button
                                onClick={() => revokeApiKeyMutation.mutate(apiKey.id)}
                                disabled={revokeApiKeyMutation.isPending}
                                className="btn-ghost text-sm p-2 text-yellow-400 hover:text-yellow-300"
                                title="Revoke key"
                              >
                                <XCircle className="w-4 h-4" />
                              </button>
                            )}
                            <button
                              onClick={() => {
                                if (confirm('Are you sure you want to delete this API key?')) {
                                  deleteApiKeyMutation.mutate(apiKey.id);
                                }
                              }}
                              disabled={deleteApiKeyMutation.isPending}
                              className="btn-ghost text-sm p-2 text-red-400 hover:text-red-300"
                              title="Delete key"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                        {apiKey.description && (
                          <p className="text-sm text-dark-400 mt-2">{apiKey.description}</p>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Create API Key Modal */}
              {showCreateKeyModal && (
                <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
                  <div className="bg-dark-800 rounded-xl p-6 w-full max-w-md mx-4 border border-dark-700">
                    <div className="flex items-center justify-between mb-4">
                      <h3 className="text-lg font-semibold text-dark-100">
                        {createdKey ? 'API Key Created' : 'Generate New API Key'}
                      </h3>
                      <button onClick={handleCloseCreateModal} className="text-dark-400 hover:text-dark-200">
                        <X className="w-5 h-5" />
                      </button>
                    </div>

                    {createdKey ? (
                      <div className="space-y-4">
                        <div className="p-4 bg-green-600/10 border border-green-600/30 rounded-lg">
                          <p className="text-sm text-green-400 mb-2">
                            Your API key has been created. Copy it now — you won't be able to see it again!
                          </p>
                          <div className="flex items-center gap-2">
                            <code className="flex-1 font-mono text-sm bg-dark-900 p-3 rounded break-all text-dark-200">
                              {createdKey}
                            </code>
                            <button
                              onClick={() => handleCopyKey(createdKey)}
                              className="btn-primary p-2"
                              title="Copy to clipboard"
                            >
                              <Copy className="w-4 h-4" />
                            </button>
                          </div>
                        </div>
                        <button onClick={handleCloseCreateModal} className="btn-secondary w-full">
                          Done
                        </button>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        <div>
                          <label className="block text-sm font-medium text-dark-300 mb-1">Name *</label>
                          <input
                            type="text"
                            className="input"
                            placeholder="e.g., Production Agent"
                            value={newKeyName}
                            onChange={(e) => setNewKeyName(e.target.value)}
                          />
                        </div>
                        <div>
                          <label className="block text-sm font-medium text-dark-300 mb-1">Description</label>
                          <input
                            type="text"
                            className="input"
                            placeholder="e.g., Used for Windows server agents"
                            value={newKeyDescription}
                            onChange={(e) => setNewKeyDescription(e.target.value)}
                          />
                        </div>
                        <div className="flex gap-3">
                          <button onClick={handleCloseCreateModal} className="btn-secondary flex-1">
                            Cancel
                          </button>
                          <button
                            onClick={handleCreateApiKey}
                            disabled={createApiKeyMutation.isPending || !newKeyName.trim()}
                            className="btn-primary flex-1 flex items-center justify-center gap-2"
                          >
                            {createApiKeyMutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
                            Generate
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Integrations Tab */}
          {activeTab === 'integrations' && (
            <div className="card p-6 space-y-6">
              <h2 className="text-lg font-semibold text-dark-100">External Integrations</h2>

              <div className="space-y-4">
                <div className="p-4 border border-dark-700 rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-[#611f69] rounded-lg flex items-center justify-center">
                        <span className="text-white font-bold">S</span>
                      </div>
                      <div>
                        <p className="font-medium text-dark-100">Slack</p>
                        <p className="text-sm text-dark-400">Send alerts to Slack</p>
                      </div>
                    </div>
                    <span className="badge bg-dark-700 text-dark-400">Not Connected</span>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-dark-300 mb-1">Webhook URL</label>
                    <input type="text" className="input" placeholder="https://hooks.slack.com/..." />
                  </div>
                </div>

                <div className="p-4 border border-dark-700 rounded-lg">
                  <div className="flex items-center justify-between mb-4">
                    <div className="flex items-center gap-3">
                      <div className="w-10 h-10 bg-[#0088cc] rounded-lg flex items-center justify-center">
                        <span className="text-white font-bold">T</span>
                      </div>
                      <div>
                        <p className="font-medium text-dark-100">Telegram</p>
                        <p className="text-sm text-dark-400">Send alerts via Telegram bot</p>
                      </div>
                    </div>
                    <span className="badge bg-dark-700 text-dark-400">Not Connected</span>
                  </div>
                  <div className="grid grid-cols-2 gap-4">
                    <div>
                      <label className="block text-sm font-medium text-dark-300 mb-1">Bot Token</label>
                      <input type="text" className="input" placeholder="123456:ABC-DEF..." />
                    </div>
                    <div>
                      <label className="block text-sm font-medium text-dark-300 mb-1">Chat ID</label>
                      <input type="text" className="input" placeholder="-1001234567890" />
                    </div>
                  </div>
                </div>
              </div>

              <div className="pt-4">
                <button
                  onClick={() => toast.success('Integrations saved (demo)')}
                  className="btn-primary"
                >
                  Save Integrations
                </button>
              </div>
            </div>
          )}

          {/* System Tab */}
          {activeTab === 'system' && (
            <div className="space-y-6">
              <div className="card p-6">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-lg font-semibold text-dark-100">System Health</h2>
                  <button
                    onClick={() => refetchHealth()}
                    disabled={healthLoading}
                    className="btn-ghost"
                  >
                    <RefreshCw className={clsx('w-4 h-4', healthLoading && 'animate-spin')} />
                  </button>
                </div>

                {healthLoading ? (
                  <div className="flex items-center justify-center py-8">
                    <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-primary-500" />
                  </div>
                ) : (
                  <div className="space-y-3">
                    {['database', 'elasticsearch', 'redis'].map((service) => {
                      const status = healthData?.data?.services?.[service];
                      const isHealthy = status === 'healthy';
                      return (
                        <div
                          key={service}
                          className="flex items-center justify-between p-3 bg-dark-700/30 rounded-lg"
                        >
                          <div className="flex items-center gap-3">
                            <Database className="w-5 h-5 text-dark-400" />
                            <span className="font-medium text-dark-200 capitalize">{service}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {isHealthy ? (
                              <CheckCircle className="w-5 h-5 text-green-400" />
                            ) : (
                              <XCircle className="w-5 h-5 text-red-400" />
                            )}
                            <span className={isHealthy ? 'text-green-400' : 'text-red-400'}>
                              {status || 'Unknown'}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              <div className="card p-6">
                <h2 className="text-lg font-semibold text-dark-100 mb-4">System Information</h2>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-dark-400">Version</span>
                    <span className="text-dark-200">1.0.0</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">Environment</span>
                    <span className="text-dark-200">Production</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-dark-400">API URL</span>
                    <span className="text-dark-200 font-mono text-xs">
                      {import.meta.env.VITE_API_URL || 'http://localhost:8000'}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
