import React, { useState } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { Zap, User } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000';

const Login = ({ onCustomLoginSuccess }) => {
  const { loginWithRedirect } = useAuth0();

  const [email, setEmail] = useState('realtest@exampletest.com');
  const [password, setPassword] = useState('Password123456');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleCustomLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-platform-secret': 'my-marketplace-private-key-123'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (data.success && data.token) {
        onCustomLoginSuccess(data.token);
        console.log('✅ Custom login successful');
      } else {
        setError(data.error || 'Invalid credentials');
      }
    } catch (err) {
      console.error('Login error:', err); // ← Added this to use the 'err' variable
      setError('Cannot connect to server. Is the backend running?');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.header}>
          <div style={styles.logo}>
            <Zap size={42} color="#4f46e5" />
            <h1 style={styles.title}>API Marketplace</h1>
          </div>
          <p style={styles.subtitle}>Sign in to your developer account</p>
        </div>

        {/* Auth0 Login */}
        <button onClick={loginWithRedirect} style={styles.auth0Button}>
          <User size={20} />
          Sign in with Auth0
        </button>

        <div style={styles.divider}>
          <span>OR</span>
        </div>

        {/* Traditional Email/Password Login */}
        <form onSubmit={handleCustomLogin}>
          <div style={styles.inputGroup}>
            <label style={styles.label}>Email Address</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={styles.input}
              required
            />
          </div>

          <div style={styles.inputGroup}>
            <label style={styles.label}>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              style={styles.input}
              required
            />
          </div>

          {error && <div style={styles.error}>{error}</div>}

          <button type="submit" disabled={loading} style={styles.customButton}>
            {loading ? 'Signing in...' : 'Sign in with Email'}
          </button>
        </form>

        <p style={styles.footer}>
          Secure login powered by Auth0 + Custom Authentication
        </p>
      </div>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    background: 'linear-gradient(135deg, #f8fafc 0%, #e0e7ff 100%)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '20px',
    fontFamily: 'Inter, system-ui, sans-serif',
  },
  card: {
    backgroundColor: '#ffffff',
    padding: '48px 40px',
    borderRadius: '20px',
    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.1)',
    width: '100%',
    maxWidth: '420px',
    border: '1px solid #e5e7eb',
  },
  header: {
    textAlign: 'center',
    marginBottom: '32px',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
    marginBottom: '12px',
  },
  title: {
    margin: 0,
    fontSize: '28px',
    fontWeight: '700',
    color: '#1f2937',
  },
  subtitle: {
    color: '#6b7280',
    margin: 0,
    fontSize: '15.5px',
  },
  auth0Button: {
    width: '100%',
    padding: '15px',
    backgroundColor: '#000000',
    color: 'white',
    border: 'none',
    borderRadius: '10px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '10px',
    marginBottom: '20px',
  },
  divider: {
    textAlign: 'center',
    margin: '24px 0',
    color: '#9ca3af',
    fontSize: '14px',
    position: 'relative',
  },
  inputGroup: {
    marginBottom: '20px',
  },
  label: {
    display: 'block',
    marginBottom: '8px',
    fontSize: '14px',
    fontWeight: '500',
    color: '#374151',
  },
  input: {
    width: '100%',
    padding: '14px 16px',
    fontSize: '16px',
    border: '1px solid #d1d5db',
    borderRadius: '10px',
  },
  customButton: {
    width: '100%',
    padding: '15px',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: '10px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
  },
  error: {
    color: '#dc2626',
    backgroundColor: '#fef2f2',
    padding: '12px',
    borderRadius: '8px',
    marginBottom: '16px',
    fontSize: '14px',
  },
  footer: {
    textAlign: 'center',
    marginTop: '24px',
    color: '#9ca3af',
    fontSize: '13px',
  },
};

export default Login;