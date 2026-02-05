import axios from 'axios';

// Use relative URL to go through Vite proxy in development
// In production, VITE_API_URL should be set to the actual backend URL
const API_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor
api.interceptors.request.use(
  (config) => {
    // Token is added in authStore
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;

    // If 401 and not already retrying, try to refresh token
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;

      try {
        // Dynamic import to avoid circular dependency
        const { useAuthStore } = await import('../stores/authStore');
        await useAuthStore.getState().refreshAccessToken();
        
        // Retry original request
        return api(originalRequest);
      } catch {
        // Refresh failed, logout
        const { useAuthStore } = await import('../stores/authStore');
        useAuthStore.getState().logout();
        window.location.href = '/login';
      }
    }

    return Promise.reject(error);
  }
);

export default api;

// API endpoints - return .data directly for react-query
export const dashboardApi = {
  getStats: () => api.get('/api/v1/dashboard/stats').then(r => r.data),
  getAlertTrends: (days = 7) => api.get(`/api/v1/dashboard/alerts/trend?hours=${days * 24}`).then(r => r.data),
  getTopAttackers: (limit = 10) => api.get(`/api/v1/dashboard/top-attackers?limit=${limit}`).then(r => r.data),
  getEventTypeDistribution: () => api.get('/api/v1/dashboard/event-types').then(r => r.data),
};

export const alertsApi = {
  list: (params?: { skip?: number; limit?: number; severity?: string; status?: string }) =>
    api.get('/api/v1/alerts', { params }).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/alerts/${id}`).then(r => r.data),
  update: (id: string, data: { status?: string; assigned_to?: string }) =>
    api.patch(`/api/v1/alerts/${id}`, data).then(r => r.data),
  acknowledge: (id: string) => api.post(`/api/v1/alerts/${id}/acknowledge`).then(r => r.data),
  getStats: () => api.get('/api/v1/alerts/stats').then(r => r.data),
};

export const logsApi = {
  search: (params: {
    query?: string;
    source?: string;
    severity?: string;
    start_time?: string;
    end_time?: string;
    skip?: number;
    limit?: number;
  }) => api.get('/api/v1/logs/search', { params }).then(r => r.data),
};

export const rulesApi = {
  list: (params?: { skip?: number; limit?: number; enabled?: boolean }) =>
    api.get('/api/v1/rules', { params }).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/rules/${id}`).then(r => r.data),
  create: (data: any) => api.post('/api/v1/rules', data).then(r => r.data),
  update: (id: string, data: any) => api.put(`/api/v1/rules/${id}`, data).then(r => r.data),
  delete: (id: string) => api.delete(`/api/v1/rules/${id}`).then(r => r.data),
  toggle: (id: string) => api.post(`/api/v1/rules/${id}/toggle`).then(r => r.data),
  test: (id: string, data: any) => api.post(`/api/v1/rules/${id}/test`, data).then(r => r.data),
};

export const incidentsApi = {
  list: (params?: { skip?: number; limit?: number; status?: string }) =>
    api.get('/api/v1/incidents', { params }).then(r => r.data),
  get: (id: string) => api.get(`/api/v1/incidents/${id}`).then(r => r.data),
  create: (data: any) => api.post('/api/v1/incidents', data).then(r => r.data),
  update: (id: string, data: any) => api.patch(`/api/v1/incidents/${id}`, data).then(r => r.data),
  addTimelineEntry: (id: string, data: any) =>
    api.post(`/api/v1/incidents/${id}/timeline`, data).then(r => r.data),
};

export const healthApi = {
  check: () => api.get('/api/v1/health').then(r => r.data),
  detailed: () => api.get('/api/v1/health/detailed').then(r => r.data),
};

export const mfaApi = {
  getStatus: () => api.get('/api/v1/auth/mfa/status').then(r => r.data),
  setup: () => api.post('/api/v1/auth/mfa/setup').then(r => r.data),
  verifySetup: (code: string) => api.post('/api/v1/auth/mfa/verify-setup', { code }).then(r => r.data),
  verifyLogin: (mfaToken: string, code: string) => 
    api.post('/api/v1/auth/mfa/verify', { mfa_token: mfaToken, code }).then(r => r.data),
  disable: (code: string) => api.post('/api/v1/auth/mfa/disable', { code }).then(r => r.data),
};

export const usersApi = {
  getProfile: () => api.get('/api/v1/users/me').then(r => r.data),
  updateProfile: (data: { full_name?: string; email?: string }) =>
    api.patch('/api/v1/users/me', data).then(r => r.data),
  changePassword: (data: { current_password: string; new_password: string }) =>
    api.post('/api/v1/users/me/change-password', data).then(r => r.data),
};

export const apiKeysApi = {
  list: () => api.get('/api/v1/users/me/api-keys').then(r => r.data),
  create: (data: { name: string; description?: string }) =>
    api.post('/api/v1/users/me/api-keys', data).then(r => r.data),
  delete: (keyId: string) =>
    api.delete(`/api/v1/users/me/api-keys/${keyId}`).then(r => r.data),
  revoke: (keyId: string) =>
    api.post(`/api/v1/users/me/api-keys/${keyId}/revoke`).then(r => r.data),
};
