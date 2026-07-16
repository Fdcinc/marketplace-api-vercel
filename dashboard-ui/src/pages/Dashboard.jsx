import React, { useState, useCallback, useEffect } from 'react';
import { Activity, CreditCard, RefreshCw, RotateCcw } from 'lucide-react';
import { BillingChat } from '../components/BillingChat';

const API_BASE_URL = 'http://localhost:8000';

const Dashboard = ({ token }) => {
  const [usageData, setUsageData] = useState({ quantity: 0, amount_due: 0, period_end: '--' });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Memoized header builder
  const getHeaders = useCallback(() => {
    const authType = localStorage.getItem('auth_type');
    const headers = {
      'Authorization': `Bearer ${token}`,
      'x-platform-secret': 'my-marketplace-private-key-123',
      'Content-Type': 'application/json'
    };
    if (authType === 'auth0') {
      headers['x-auth-source'] = 'auth0';
    }
    return headers;
  }, [token]);

  // Fetch logic with encapsulated state management
  const fetchUsage = useCallback(async (showLoading = true) => {
    if (!token) {
      setError("No authentication token found. Please login again.");
      setLoading(false);
      return;
    }

    if (showLoading) setLoading(true);
    setError(null);

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/usage`, {
        method: 'GET',
        headers: getHeaders()
      });

      if (response.status === 401) throw new Error("Unauthorized: Please check your login session.");
      if (!response.ok) throw new Error(`Server error: ${response.status}`);

      const json = await response.json();
      if (json.success) {
        setUsageData(json.data);
      } else {
        setError(json.error || 'Failed to load data');
      }
    } catch (err) {
      setError(err.message || 'Could not connect to backend.');
    } finally {
      setLoading(false);
    }
  }, [token, getHeaders]);

  // Trigger fetch with a 500ms delay to ensure stable UI mounting
  useEffect(() => {
    const timer = setTimeout(() => {
      fetchUsage(true);
    }, 500);

    return () => clearTimeout(timer);
  }, [fetchUsage]);

  const resetUsage = async () => {
    if (!window.confirm('Reset usage counter to 0? (For testing only)')) return;

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/reset-usage`, {
        method: 'POST',
        headers: getHeaders()
      });

      const json = await response.json();
      if (json.success) {
        alert(`✅ Usage reset successfully!`);
        fetchUsage(false);
      } else {
        alert(json.error || 'Failed to reset usage');
      }
    } catch (err) {
      console.error('Reset usage error:', err);
      alert('Error resetting usage.');
    }
  };
 return (
    <div>
      <div style={styles.header}>
        <div>
          <h1 style={styles.pageTitle}>Dashboard</h1>
          <p style={styles.subtitle}>Real-time usage and billing overview</p>
        </div>
      </div>

      {error && <div style={styles.errorBanner}>{error}</div>}

      <div style={styles.grid}>
        {/* Trial Status Card */}
        {usageData.isTrial && (
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <Activity size={24} color="#f59e0b" />
              <span>Trial Status</span>
            </div>
            <h2 style={styles.stat}>
              {loading ? '...' : usageData.trialRemaining}
            </h2>
            <p style={styles.subtext}>Requests remaining of {usageData.trialLimit}</p>
            <div style={styles.progressContainer}>
              <div style={{ 
                ...styles.progressBar, 
                width: `${Math.min(100, ((usageData.trialLimit - usageData.trialRemaining) / usageData.trialLimit) * 100)}%` 
              }}></div>
            </div>
          </div>
        )}

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <Activity size={24} color="#4f46e5" />
            <span>Total API Requests</span>
          </div>
          <h2 style={styles.stat}>
            {loading ? '...' : (usageData.quantity || 0).toLocaleString()}
          </h2>
          <p style={styles.subtext}>Current billing cycle</p>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <CreditCard size={24} color="#10b981" />
            <span>Accrued Cost</span>
          </div>
          <h2 style={styles.stat}>
            {loading ? '...' : `€${(usageData.amount_due || 0).toFixed(2)}`}
          </h2>
          <p style={styles.subtext}>Next invoice: {usageData.period_end}</p>
        </div>
      </div>

      <div style={styles.buttonGroup}>
        <button onClick={() => fetchUsage(true)} disabled={loading} style={styles.refreshButton}>
          <RefreshCw size={18} style={{ marginRight: '8px' }} />
          {loading ? 'Refreshing...' : 'Refresh Data'}
        </button>

        <button onClick={resetUsage} style={styles.resetButton}>
          <RotateCcw size={18} style={{ marginRight: '8px' }} />
          Reset Usage (Dev)
        </button>
      </div>

      <div style={{ marginTop: '40px' }}>
        <BillingChat token={token} />
      </div>
    </div>
  );
};

const styles = {
  header: { marginBottom: '40px' },
  pageTitle: { fontSize: '32px', fontWeight: '700', color: '#1f2937', margin: '0 0 8px 0' },
  subtitle: { color: '#6b7280', fontSize: '16px', margin: 0 },
  errorBanner: { backgroundColor: '#fef2f2', color: '#dc2626', padding: '14px 20px', borderRadius: '10px', marginBottom: '24px', border: '1px solid #fecaca' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '24px', marginBottom: '40px' },
  card: { backgroundColor: '#ffffff', padding: '32px', borderRadius: '16px', boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)', border: '1px solid #e5e7eb' },
  cardHeader: { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '20px', color: '#4b5563', fontWeight: '600' },
  stat: { margin: '0 0 8px 0', fontSize: '48px', fontWeight: '700', color: '#1f2937' },
  subtext: { color: '#6b7280', margin: 0, fontSize: '15px' },
  buttonGroup: { display: 'flex', gap: '12px', flexWrap: 'wrap' },
  refreshButton: { display: 'flex', alignItems: 'center', padding: '14px 24px', backgroundColor: '#4f46e5', color: 'white', border: 'none', borderRadius: '10px', fontSize: '16px', fontWeight: '600', cursor: 'pointer' },
  resetButton: { display: 'flex', alignItems: 'center', padding: '14px 24px', backgroundColor: '#f59e0b', color: 'white', border: 'none', borderRadius: '10px', fontSize: '16px', fontWeight: '600', cursor: 'pointer' },
  progressContainer: { width: '100%', backgroundColor: '#e5e7eb', borderRadius: '10px', height: '10px', marginTop: '20px', overflow: 'hidden' },
  progressBar: { backgroundColor: '#f59e0b', height: '100%', transition: 'width 0.5s ease-in-out' }
};

export default Dashboard;