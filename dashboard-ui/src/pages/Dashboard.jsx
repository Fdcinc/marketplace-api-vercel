import React, { useState, useCallback, useRef, useEffect } from 'react';
import { Activity, CreditCard, LogOut, RefreshCw, Zap } from 'lucide-react';

const API_BASE_URL = 'http://localhost:5000';

const Dashboard = ({ token, onLogout }) => {
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
        onLogout();
        return;
      }

      if (!response.ok) throw new Error('Failed to fetch data');

      const json = await response.json();
      if (json.success) {
        setUsageData(json.data);
      } else {
        setError(json.error || 'Failed to load usage data');
      }
    } catch (err) {
      setError('Failed to fetch usage data');
      console.error(err);
    } finally {
      setIsLoading(false);
    }
  }, [token, onLogout]);

  useEffect(() => {
    if (!hasFetched.current) {
      fetchUsage();
      hasFetched.current = true;
    }
  }, [fetchUsage]);

  return (
    <div style={styles.container}>
      {/* Header */}
      <header style={styles.header}>
        <div style={styles.headerContent}>
          <div style={styles.logo}>
            <Zap size={28} color="#4f46e5" />
            <h1 style={styles.title}>API Marketplace</h1>
          </div>
          <button onClick={onLogout} style={styles.logoutBtn}>
            <LogOut size={18} /> Logout
          </button>
        </div>
      </header>

      {error && <div style={styles.errorBanner}>{error}</div>}

      <div style={styles.dashboardContent}>
        <div style={styles.grid}>
          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <Activity size={22} color="#4f46e5" />
              <span>Total API Requests</span>
            </div>
            <h2 style={styles.stat}>
              {isLoading ? '...' : (usageData.quantity || 0).toLocaleString()}
            </h2>
            <p style={styles.subtext}>Current billing cycle</p>
          </div>

          <div style={styles.card}>
            <div style={styles.cardHeader}>
              <CreditCard size={22} color="#10b981" />
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
          <RefreshCw size={18} style={{ marginRight: '8px' }} />
          {isLoading ? 'Refreshing...' : 'Refresh Data'}
        </button>
      </div>
    </div>
  );
};

const styles = {
  container: {
    minHeight: '100vh',
    background: '#f8fafc',
    fontFamily: 'Inter, system-ui, -apple-system, sans-serif',
  },
  header: {
    backgroundColor: '#ffffff',
    borderBottom: '1px solid #e5e7eb',
    padding: '16px 32px',
    position: 'sticky',
    top: 0,
    zIndex: 10,
  },
  headerContent: {
    maxWidth: '1200px',
    margin: '0 auto',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
  },
  title: {
    margin: 0,
    fontSize: '24px',
    fontWeight: '700',
    color: '#1f2937',
  },
  logoutBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    padding: '8px 16px',
    backgroundColor: '#f3f4f6',
    color: '#374151',
    border: 'none',
    borderRadius: '8px',
    cursor: 'pointer',
    fontSize: '14px',
  },
  errorBanner: {
    backgroundColor: '#fef2f2',
    color: '#dc2626',
    padding: '14px 32px',
    textAlign: 'center',
  },
  dashboardContent: {
    maxWidth: '1200px',
    margin: '40px auto',
    padding: '0 32px',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))',
    gap: '24px',
    marginBottom: '32px',
  },
  card: {
    backgroundColor: '#ffffff',
    padding: '28px',
    borderRadius: '16px',
    boxShadow: '0 4px 6px -1px rgba(0, 0, 0, 0.1)',
    border: '1px solid #e5e7eb',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    marginBottom: '16px',
    color: '#4b5563',
    fontWeight: '500',
  },
  stat: {
    margin: '0 0 8px 0',
    fontSize: '42px',
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
  },
};

export default Dashboard;