import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Activity, CreditCard, RefreshCw, Zap } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000';

const Dashboard = ({ token }) => {
  const [usageData, setUsageData] = useState({
    quantity: 0,
    amount_due: 0,
    period_end: '--'
  });
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState(null);

  const hasFetched = useRef(false);

  const fetchUsage = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) setIsLoading(true);
    setError(null);

    if (!token) {
      setError('No authentication token found. Please login again.');
      setIsLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/usage`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
          'x-platform-secret': 'my-marketplace-private-key-123',
          'Content-Type': 'application/json'
        }
      });

      if (response.status === 401) {
        setError('Session expired. Please login again.');
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch usage data');

      const json = await response.json();
      if (json.success) {
        setUsageData(json.data);
      } else {
        setError(json.error || 'Failed to load data');
      }
    } catch (err) {
      console.error(err);
      setError('Failed to fetch usage data. Is the backend running?');
    } finally {
      setIsLoading(false);
    }
  }, [token]);

  useEffect(() => {
    if (!hasFetched.current) {
      fetchUsage();
      hasFetched.current = true;
    }
  }, [fetchUsage]);

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
        {/* Total Requests Card */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <Activity size={24} color="#4f46e5" />
            <span>Total API Requests</span>
          </div>
          <h2 style={styles.stat}>
            {isLoading ? '...' : (usageData.quantity || 0).toLocaleString()}
          </h2>
          <p style={styles.subtext}>Current billing cycle</p>
        </div>

        {/* Accrued Cost Card */}
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <CreditCard size={24} color="#10b981" />
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
        style={styles.refreshButton}
      >
        <RefreshCw size={18} style={{ marginRight: '10px' }} />
        {isLoading ? 'Refreshing...' : 'Refresh Data'}
      </button>
    </div>
  );
};

const styles = {
  header: {
    marginBottom: '40px',
  },
  pageTitle: {
    fontSize: '32px',
    fontWeight: '700',
    color: '#1f2937',
    margin: '0 0 8px 0',
  },
  subtitle: {
    color: '#6b7280',
    fontSize: '16px',
    margin: 0,
  },
  errorBanner: {
    backgroundColor: '#fef2f2',
    color: '#dc2626',
    padding: '14px 20px',
    borderRadius: '10px',
    marginBottom: '24px',
    border: '1px solid #fecaca',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))',
    gap: '24px',
    marginBottom: '40px',
  },
  card: {
    backgroundColor: '#ffffff',
    padding: '32px',
    borderRadius: '16px',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    border: '1px solid #e5e7eb',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '20px',
    color: '#4b5563',
    fontWeight: '600',
    fontSize: '15px',
  },
  stat: {
    margin: '0 0 8px 0',
    fontSize: '48px',
    fontWeight: '700',
    color: '#1f2937',
  },
  subtext: {
    color: '#6b7280',
    margin: 0,
    fontSize: '15px',
  },
  refreshButton: {
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '14px 28px',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: '10px',
    fontSize: '16px',
    fontWeight: '600',
    cursor: 'pointer',
    width: 'fit-content',
  },
};

export default Dashboard;