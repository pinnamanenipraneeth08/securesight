import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import api from '../services/api';

interface User {
  id: string;
  email: string;
  full_name: string;
  role: string;
}

interface MFAState {
  required: boolean;
  token: string | null;
}

interface AuthState {
  user: User | null;
  token: string | null;
  refreshToken: string | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  error: string | null;
  mfa: MFAState;
  login: (email: string, password: string) => Promise<boolean>; // returns true if MFA required
  verifyMFA: (code: string) => Promise<void>;
  logout: () => void;
  refreshAccessToken: () => Promise<void>;
  clearError: () => void;
  clearMFA: () => void;
  setUser: (user: User) => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      user: null,
      token: null,
      refreshToken: null,
      isAuthenticated: false,
      isLoading: false,
      error: null,
      mfa: { required: false, token: null },

      login: async (email: string, password: string) => {
        set({ isLoading: true, error: null, mfa: { required: false, token: null } });
        try {
          // OAuth2 expects form-urlencoded data
          const formData = new URLSearchParams();
          formData.append('username', email);
          formData.append('password', password);
          
          const response = await api.post('/api/v1/auth/login', formData, {
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
            },
          });
          
          // Check if MFA is required
          if (response.data.mfa_required) {
            set({
              isLoading: false,
              mfa: { required: true, token: response.data.mfa_token },
            });
            return true; // MFA required
          }
          
          const { access_token, refresh_token, user } = response.data;
          
          set({
            token: access_token,
            refreshToken: refresh_token,
            user,
            isAuthenticated: true,
            isLoading: false,
          });
          
          // Set default auth header
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
          return false; // No MFA required
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.response?.data?.detail || 'Login failed',
          });
          throw error;
        }
      },

      verifyMFA: async (code: string) => {
        const { mfa } = get();
        if (!mfa.token) {
          throw new Error('No MFA token available');
        }
        
        set({ isLoading: true, error: null });
        try {
          const response = await api.post('/api/v1/auth/mfa/verify', {
            mfa_token: mfa.token,
            code,
          });
          
          const { access_token, refresh_token, user } = response.data;
          
          set({
            token: access_token,
            refreshToken: refresh_token,
            user,
            isAuthenticated: true,
            isLoading: false,
            mfa: { required: false, token: null },
          });
          
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        } catch (error: any) {
          set({
            isLoading: false,
            error: error.response?.data?.detail || 'MFA verification failed',
          });
          throw error;
        }
      },

      logout: () => {
        set({
          user: null,
          token: null,
          refreshToken: null,
          isAuthenticated: false,
          mfa: { required: false, token: null },
        });
        delete api.defaults.headers.common['Authorization'];
      },

      refreshAccessToken: async () => {
        const { refreshToken } = get();
        if (!refreshToken) {
          get().logout();
          return;
        }

        try {
          const response = await api.post('/api/v1/auth/refresh', {
            refresh_token: refreshToken,
          });
          
          const { access_token } = response.data;
          set({ token: access_token });
          api.defaults.headers.common['Authorization'] = `Bearer ${access_token}`;
        } catch {
          get().logout();
        }
      },

      clearError: () => set({ error: null }),
      clearMFA: () => set({ mfa: { required: false, token: null } }),
      setUser: (user: User) => set({ user }),
    }),
    {
      name: 'auth-storage',
      partialize: (state) => ({
        token: state.token,
        refreshToken: state.refreshToken,
        user: state.user,
        isAuthenticated: state.isAuthenticated,
      }),
    }
  )
);

// Initialize auth header on load
const token = useAuthStore.getState().token;
if (token) {
  api.defaults.headers.common['Authorization'] = `Bearer ${token}`;
}
