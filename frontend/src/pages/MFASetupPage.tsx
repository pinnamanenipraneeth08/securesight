import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { mfaApi } from '../services/api';
import { Shield, Smartphone, CheckCircle, AlertCircle, Copy } from 'lucide-react';
import toast from 'react-hot-toast';

interface MFASetupData {
  secret: string;
  qr_code: string;
  provisioning_uri: string;
}

export default function MFASetupPage() {
  const [status, setStatus] = useState<{ mfa_enabled: boolean; mfa_configured: boolean } | null>(null);
  const [setupData, setSetupData] = useState<MFASetupData | null>(null);
  const [verifyCode, setVerifyCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [step, setStep] = useState<'status' | 'setup' | 'verify' | 'disable'>('status');
  const navigate = useNavigate();

  useEffect(() => {
    fetchStatus();
  }, []);

  const fetchStatus = async () => {
    try {
      const data = await mfaApi.getStatus();
      setStatus(data);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to fetch MFA status');
    }
  };

  const handleSetup = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await mfaApi.setup();
      setSetupData(data);
      setStep('setup');
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to initialize MFA setup');
    } finally {
      setIsLoading(false);
    }
  };

  const handleVerifySetup = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await mfaApi.verifySetup(verifyCode);
      toast.success('MFA successfully enabled!');
      setStep('status');
      setSetupData(null);
      setVerifyCode('');
      fetchStatus();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to verify code');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDisable = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError(null);
    try {
      await mfaApi.disable(disableCode);
      toast.success('MFA has been disabled');
      setStep('status');
      setDisableCode('');
      fetchStatus();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to disable MFA');
    } finally {
      setIsLoading(false);
    }
  };

  const copySecret = () => {
    if (setupData?.secret) {
      navigator.clipboard.writeText(setupData.secret);
      toast.success('Secret copied to clipboard');
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-6">
      <div className="flex items-center gap-3 mb-6">
        <div className="p-3 rounded-lg bg-primary-600/20 border border-primary-500/30">
          <Shield className="w-6 h-6 text-primary-500" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-dark-100">Two-Factor Authentication</h1>
          <p className="text-dark-400 text-sm">Add an extra layer of security to your account</p>
        </div>
      </div>

      {error && (
        <div className="flex items-center gap-2 p-3 mb-4 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 text-sm">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          {error}
        </div>
      )}

      {/* Status View */}
      {step === 'status' && status && (
        <div className="card p-6">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center gap-3">
              <Smartphone className="w-8 h-8 text-dark-400" />
              <div>
                <h3 className="font-semibold text-dark-100">Authenticator App</h3>
                <p className="text-sm text-dark-400">
                  Use Google Authenticator, Microsoft Authenticator, or similar apps
                </p>
              </div>
            </div>
            <div className={`px-3 py-1 rounded-full text-sm font-medium ${
              status.mfa_enabled 
                ? 'bg-green-500/20 text-green-400' 
                : 'bg-dark-700 text-dark-400'
            }`}>
              {status.mfa_enabled ? 'Enabled' : 'Disabled'}
            </div>
          </div>

          {status.mfa_enabled ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400">
                <CheckCircle className="w-5 h-5" />
                <span>Your account is protected with two-factor authentication</span>
              </div>
              <button
                onClick={() => setStep('disable')}
                className="btn-secondary w-full"
              >
                Disable Two-Factor Authentication
              </button>
            </div>
          ) : (
            <button
              onClick={handleSetup}
              disabled={isLoading}
              className="btn-primary w-full"
            >
              {isLoading ? 'Setting up...' : 'Enable Two-Factor Authentication'}
            </button>
          )}
        </div>
      )}

      {/* Setup View - QR Code */}
      {step === 'setup' && setupData && (
        <div className="card p-6">
          <h3 className="font-semibold text-dark-100 mb-4">Step 1: Scan QR Code</h3>
          <p className="text-dark-400 text-sm mb-4">
            Open your authenticator app and scan the QR code below, or enter the secret key manually.
          </p>

          <div className="flex justify-center mb-6">
            <div className="bg-white p-4 rounded-lg">
              <img src={setupData.qr_code} alt="MFA QR Code" className="w-48 h-48" />
            </div>
          </div>

          <div className="mb-6">
            <label className="block text-sm font-medium text-dark-300 mb-2">
              Or enter this secret key manually:
            </label>
            <div className="flex items-center gap-2">
              <code className="flex-1 p-3 bg-dark-800 rounded-lg text-sm font-mono text-dark-200 break-all">
                {setupData.secret}
              </code>
              <button
                onClick={copySecret}
                className="p-3 rounded-lg bg-dark-700 hover:bg-dark-600 text-dark-300"
                title="Copy secret"
              >
                <Copy className="w-5 h-5" />
              </button>
            </div>
          </div>

          <hr className="border-dark-700 my-6" />

          <h3 className="font-semibold text-dark-100 mb-4">Step 2: Verify Setup</h3>
          <p className="text-dark-400 text-sm mb-4">
            Enter the 6-digit code from your authenticator app to complete setup.
          </p>

          <form onSubmit={handleVerifySetup} className="space-y-4">
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={verifyCode}
              onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="input text-center text-2xl tracking-widest"
              placeholder="000000"
              maxLength={6}
              required
            />

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => {
                  setStep('status');
                  setSetupData(null);
                  setVerifyCode('');
                }}
                className="btn-secondary flex-1"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isLoading || verifyCode.length !== 6}
                className="btn-primary flex-1"
              >
                {isLoading ? 'Verifying...' : 'Verify & Enable'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Disable View */}
      {step === 'disable' && (
        <div className="card p-6">
          <h3 className="font-semibold text-dark-100 mb-4">Disable Two-Factor Authentication</h3>
          <div className="flex items-center gap-2 p-3 mb-4 bg-yellow-500/10 border border-yellow-500/30 rounded-lg text-yellow-400 text-sm">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>
              Disabling 2FA will make your account less secure. You'll only need your password to sign in.
            </span>
          </div>

          <p className="text-dark-400 text-sm mb-4">
            Enter a code from your authenticator app to confirm.
          </p>

          <form onSubmit={handleDisable} className="space-y-4">
            <input
              type="text"
              inputMode="numeric"
              pattern="[0-9]*"
              value={disableCode}
              onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
              className="input text-center text-2xl tracking-widest"
              placeholder="000000"
              maxLength={6}
              required
            />

            <div className="flex gap-3">
              <button
                type="button"
                onClick={() => {
                  setStep('status');
                  setDisableCode('');
                  setError(null);
                }}
                className="btn-secondary flex-1"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isLoading || disableCode.length !== 6}
                className="bg-red-600 hover:bg-red-700 text-white font-medium py-2 px-4 rounded-lg transition-colors flex-1"
              >
                {isLoading ? 'Disabling...' : 'Disable 2FA'}
              </button>
            </div>
          </form>
        </div>
      )}

      <button
        onClick={() => navigate('/settings')}
        className="mt-4 text-dark-400 hover:text-dark-200 text-sm"
      >
        ← Back to Settings
      </button>
    </div>
  );
}
