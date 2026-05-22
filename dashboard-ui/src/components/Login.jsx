import React, { useState } from 'react';
import { User, Zap } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000';

const Login = ({ onLoginSuccess }) => {
  const [email, setEmail] = useState('realtest@exampletest.com');
  const [password, setPassword] = useState('Password123456');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLogin = async (e) => {
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
        onLoginSuccess(data.token);
        console.log('✅ Login successful!');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Cannot connect to server. Is the backend running?');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <div style={styles.loginHeader}>
          <div style={styles.logo}>
            <Zap size={42} color="#4f46e5" />
            <h1 style={styles.marketplaceName}>API Marketplace</h1>
          </div>
          <p style={styles.subtitle}>Sign in to your developer account</p>
        </div>

        <form onSubmit={handleLogin}>
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

          <button type="submit" disabled={loading} style={styles.button}>
            {loading ? 'Signing in...' : 'Sign In'}
          </button>
        </form>
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
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
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
  loginHeader: {
    textAlign: 'center',
    marginBottom: '40px',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '12px',
    marginBottom: '12px',
  },
  marketplaceName: {
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
  inputGroup: {
    marginBottom: '24px',
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
    outline: 'none',
  },
  button: {
    width: '100%',
    padding: '15px',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: '10px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    marginTop: '8px',
  },
  error: {
    color: '#dc2626',
    backgroundColor: '#fef2f2',
    border: '1px solid #fecaca',
    padding: '12px 16px',
    borderRadius: '10px',
    marginBottom: '20px',
    fontSize: '14px',
  },
};

export default Login;