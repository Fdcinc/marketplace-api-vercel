import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Activity, CreditCard, LogOut, RefreshCw, User } from 'lucide-react';

// ================== CONFIGURATION ==================
const API_BASE_URL = 'http://localhost:5000';   // ← Make sure this matches your backend port

const App = () => {
  const [usageData, setUsageData] = useState({ 
    quantity: 0, 
    amount_due: 0, 
    period_end: '--' 
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  const [loginForm, setLoginForm] = useState({
    email: 'realtest@exampletest.com',
    password: 'Password123456'
  });
  const [loginLoading, setLoginLoading] = useState(false);

  const hasFetched = useRef(false);

  const getCurrentToken = useCallback(() => {
    const current = localStorage.getItem('token');
    setToken(current);
    return current;
  }, []);

  const handleLogin = async (e) => {
    e.preventDefault();
    setLoginLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-platform-secret': 'my-marketplace-private-key-123'
        },
        body: JSON.stringify(loginForm)
      });

      const data = await response.json();

      if (data.success && data.token) {
        localStorage.setItem('token', data.token);
        setToken(data.token);
        setError(null);
        console.log('✅ Login successful!');
      } else {
        setError(data.error || 'Login failed');
      }
    } catch {
      setError(`Cannot connect to server. Is backend running on ${API_BASE_URL}?`);
    } finally {
      setLoginLoading(false);
    }
  };

  const fetchUsage = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) setIsLoading(true);
    setError(null);

    const currentToken = getCurrentToken();
    if (!currentToken) {
      setError('Please log in to view your dashboard');
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/usage`, {
        method: 'GET',
        headers: { 
          'Authorization': `Bearer ${currentToken}`,
          'x-platform-secret': 'my-marketplace-private-key-123',
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 401) {
        localStorage.removeItem('token');
        setToken(null);
        setError('Session expired. Please login again.');
        return;
      }

      if (!response.ok) throw new Error(`Server error: ${response.status}`);

      const json = await response.json();
      if (json.success) {
        setUsageData(json.data);
      } else {
        throw new Error(json.error || 'Failed to load data');
      }
    } catch (err) {
      console.error(err);
      setError('Failed to fetch usage data');
    } finally {
      setIsLoading(false);
    }
  }, [getCurrentToken]);

  useEffect(() => {
    if (!hasFetched.current) {
      fetchUsage();
      hasFetched.current = true;
    }
  }, [fetchUsage]);

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
    setUsageData({ quantity: 0, amount_due: 0, period_end: '--' });
    setError(null);
  };

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <h1>Developer Dashboard</h1>
            <p>Real-time usage monitoring</p>
          </div>
          
          {token && (
            <button onClick={handleLogout} style={styles.logoutBtn}>
              <LogOut size={18} /> Logout
            </button>
          )}
        </div>
      </header>

      {error && <div style={styles.errorBanner}>⚠️ {error}</div>}

      {!token && (
        <div style={styles.loginCard}>
          <div style={{ textAlign: 'center', marginBottom: '24px' }}>
            <User size={48} color="#635bff" />
            <h2>Sign In</h2>
            <p>Access your usage dashboard</p>
          </div>

          <form onSubmit={handleLogin}>
            <input
              type="email"
              placeholder="Email"
              value={loginForm.email}
              onChange={(e) => setLoginForm({ ...loginForm, email: e.target.value })}
              style={styles.input}
              required
            />
            <input
              type="password"
              placeholder="Password"
              value={loginForm.password}
              onChange={(e) => setLoginForm({ ...loginForm, password: e.target.value })}
              style={styles.input}
              required
            />

            <button 
              type="submit" 
              disabled={loginLoading}
              style={styles.loginButton}
            >
              {loginLoading ? 'Signing in...' : 'Sign In'}
            </button>
          </form>
        </div>
      )}

      {token && (
        <>
          <div style={styles.grid}>
            <div style={styles.card}>
              <div style={styles.cardHeader}>
                <Activity size={20} color="#635bff" />
                <span>Total API Requests</span>
              </div>
              <h2 style={styles.stat}>
                {isLoading ? '...' : (usageData.quantity || 0).toLocaleString()}
              </h2>
              <p style={styles.subtext}>Current billing cycle</p>
            </div>

            <div style={styles.card}>
              <div style={styles.cardHeader}>
                <CreditCard size={20} color="#24b47e" />
                <span>Accrued Cost</span>
              </div>
              <h2 style={styles.stat}>
                {isLoading ? '...' : `€${(usageData.amount_due || 0).toFixed(2)}`}
              </h2>
              <p style={styles.subtext}>Next invoice: {usageData.period_end}</p>
            </div>
          </div>

          <button 
            onClick={() => fetchUsage(true)} 
            disabled={isLoading}
            style={styles.button}
          >
            <RefreshCw size={18} style={{ marginRight: '8px' }} />
            {isLoading ? 'Refreshing...' : 'Refresh Data'}
          </button>
        </>
      )}
    </div>
  );
};

const styles = { /* ... keep your existing styles ... */ };

export default App;