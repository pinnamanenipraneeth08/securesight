import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuthStore } from '../stores/authStore';
import { Shield, Eye, EyeOff, AlertCircle, Smartphone } from 'lucide-react';
import toast from 'react-hot-toast';

export default function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const { login, verifyMFA, isLoading, error, clearError, mfa, clearMFA } = useAuthStore();
  const navigate = useNavigate();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    try {
      const mfaRequired = await login(email, password);
      if (!mfaRequired) {
        toast.success('Welcome to SecureSight!');
        navigate('/dashboard');
      }
      // If MFA required, the UI will show the MFA form
    } catch {
      // Error is handled in store
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    clearError();

    try {
      await verifyMFA(mfaCode);
      toast.success('Welcome to SecureSight!');
      navigate('/dashboard');
    } catch {
      // Error is handled in store
    }
  };

  const handleBackToLogin = () => {
    clearMFA();
    setMfaCode('');
    clearError();
  };

  // MFA verification form
  if (mfa.required) {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center bg-dark-900 p-4">
        <div className="absolute inset-0 bg-gradient-to-br from-primary-900/20 via-dark-900 to-dark-900" />

        <div className="relative w-full max-w-md">
          <div className="flex flex-col items-center mb-8">
            <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-primary-600/20 border border-primary-500/30 mb-4">
              <Smartphone className="w-8 h-8 text-primary-500" />
            </div>
            <h1 className="text-3xl font-bold text-gradient">Verification Required</h1>
            <p className="text-dark-400 mt-1">Enter the code from your authenticator app</p>
          </div>

          <div className="card p-8">
            <h2 className="text-xl font-semibold text-center mb-6">Two-Factor Authentication</h2>

            {error && (
              <div className="flex items-center gap-2 p-3 mb-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                {error}
              </div>
            )}

            <form onSubmit={handleMfaSubmit} className="space-y-4">
              <div>
                <label htmlFor="mfaCode" className="block text-sm font-medium text-dark-300 mb-1">
                  Verification Code
                </label>
                <input
                  id="mfaCode"
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  autoComplete="one-time-code"
                  value={mfaCode}
                  onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  className="input text-center text-2xl tracking-widest"
                  placeholder="000000"
                  maxLength={6}
                  required
                />
                <p className="text-dark-500 text-xs mt-2">
                  Open Google Authenticator, Microsoft Authenticator, or your preferred app
                </p>
              </div>

              <button
                type="submit"
                disabled={isLoading || mfaCode.length !== 6}
                className="btn-primary w-full py-2.5"
              >
                {isLoading ? (
                  <span className="flex items-center gap-2 justify-center">
                    <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24">
                      <circle
                        className="opacity-25"
                        cx="12"
                        cy="12"
                        r="10"
                        stroke="currentColor"
                        strokeWidth="4"
                        fill="none"
                      />
                      <path
                        className="opacity-75"
                        fill="currentColor"
                        d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                      />
                    </svg>
                    Verifying...
                  </span>
                ) : (
                  'Verify'
                )}
              </button>

              <button
                type="button"
                onClick={handleBackToLogin}
                className="w-full text-center text-dark-400 hover:text-dark-200 text-sm"
              >
                Back to login
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-dark-900 p-4">
      {/* Background gradient */}
      <div className="absolute inset-0 bg-gradient-to-br from-primary-900/20 via-dark-900 to-dark-900" />

      <div className="relative w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-primary-600/20 border border-primary-500/30 mb-4">
            <Shield className="w-8 h-8 text-primary-500" />
          </div>
          <h1 className="text-3xl font-bold text-gradient">SecureSight</h1>
          <p className="text-dark-400 mt-1">SIEM & Threat Detection Platform</p>
        </div>

        {/* Login card */}
        <div className="card p-8">
          <h2 className="text-xl font-semibold text-center mb-6">Sign in to your account</h2>

          {error && (
            <div className="flex items-center gap-2 p-3 mb-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              {error}
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-dark-300 mb-1">
                Email address
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input"
                placeholder="admin@securesight.local"
                required
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-sm font-medium text-dark-300 mb-1">
                Password
              </label>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input pr-10"
                  placeholder="••••••••"
                  required
                />
                <button
                  type="button"
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-dark-400 hover:text-dark-200"
                  onClick={() => setShowPassword(!showPassword)}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="btn-primary w-full py-2.5"
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24">
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                      fill="none"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
                    />
                  </svg>
                  Signing in...
                </span>
              ) : (
                'Sign in'
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-dark-500 text-sm mt-6">
          SecureSight v1.0.0 - Enterprise SIEM Platform
        </p>
      </div>
    </div>
  );
}
