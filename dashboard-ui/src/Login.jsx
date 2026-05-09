import React, { useState } from 'react';

const Login = () => {
  const [email, setEmail] = useState('realtest@exampletest.com');
  const [password, setPassword] = useState('Password123456');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8000/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-platform-secret': 'my-marketplace-private-key-123'
        },
        body: JSON.stringify({ email, password })
      });

      const data = await response.json();

      if (data.success) {
        localStorage.setItem('token', data.token);
        console.log('✅ Login successful - Token saved');
        window.location.reload(); // Refresh to show dashboard
      } else {
        setError(data.error || 'Login failed');
      }
    } catch (err) {
      setError('Connection error. Is the backend running?');
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={styles.container}>
      <div style={styles.card}>
        <h1 style={styles.title}>Login</h1>
        <p style={styles.subtitle}>Access your Developer Dashboard</p>

        <form onSubmit={handleLogin}>
          <div style={styles.inputGroup}>
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              style={styles.input}
              required
            />
          </div>

          <div style={styles.inputGroup}>
            <label>Password</label>
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
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </form>
      </div>
    </div>
  );
};

const styles = {
  container: {
    padding: '40px',
    backgroundColor: '#f6f9fc',
    minHeight: '100vh',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    fontFamily: 'Inter, system-ui'
  },
  card: {
    backgroundColor: '#fff',
    padding: '40px',
    borderRadius: '12px',
    boxShadow: '0 4px 6px rgba(50,50,93,.11)',
    width: '100%',
    maxWidth: '400px'
  },
  title: { margin: '0 0 8px 0', fontSize: '28px' },
  subtitle: { color: '#6b7280', marginBottom: '30px' },
  inputGroup: { marginBottom: '20px' },
  input: {
    width: '100%',
    padding: '12px',
    border: '1px solid #e5e7eb',
    borderRadius: '6px',
    fontSize: '16px'
  },
  button: {
    width: '100%',
    padding: '14px',
    backgroundColor: '#635bff',
    color: '#fff',
    border: 'none',
    borderRadius: '8px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    marginTop: '10px'
  },
  error: {
    color: '#b91c1c',
    backgroundColor: '#fee2e2',
    padding: '10px',
    borderRadius: '6px',
    marginBottom: '15px'
  }
};

export default Login;