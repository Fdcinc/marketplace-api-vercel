import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Activity, CreditCard } from 'lucide-react';

const App = () => {
  const [usageData, setUsageData] = useState({ quantity: 0, amount_due: 0, period_end: '--' });
  const [isLoading, setIsLoading] = useState(true); 
  const [error, setError] = useState(null);
  
  // Track if we have already performed the initial fetch
  const hasFetched = useRef(false);

  const fetchUsage = useCallback(async (isManualRefresh = false) => {
    if (isManualRefresh) setIsLoading(true);
    setError(null);

    try {
      const response = await fetch('http://localhost:8000/api/v1/auth/usage', {
        headers: { 
          'Authorization': `Bearer ${localStorage.getItem('token')}`,
          'x-platform-secret': 'my-marketplace-private-key-123', // Ensure this matches your backend's expected secret
          'apikey': 'YdieukKvtjIYuYMpM8nLxgHFGoqkhYjEb/uYaWMnZ80=',
        }
      });

      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);

      const json = await response.json();
      if (json.success) {
        setUsageData(json.data);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    // Only fetch if we haven't already
    if (!hasFetched.current) {
      fetchUsage();
      hasFetched.current = true;
    }
  }, [fetchUsage]);

  return (
    <div style={styles.container}>
      <header style={styles.header}>
        <h1>Developer Dashboard</h1>
        <p>Real-time usage for <strong>realtest@exampletest.com</strong></p>
      </header>

      {error && <div style={styles.errorBanner}>⚠️ {error}</div>}

      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <Activity size={20} color="#635bff" />
            <span>Total API Requests</span>
          </div>
          {/* We check isLoading here to show a placeholder */}
          <h2 style={styles.stat}>{isLoading && usageData.quantity === 0 ? '...' : usageData.quantity}</h2>
          <p style={styles.subtext}>Current billing cycle</p>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <CreditCard size={20} color="#24b47e" />
            <span>Accrued Cost</span>
          </div>
          <h2 style={styles.stat}>
            {isLoading && usageData.amount_due === 0 ? '...' : `€${usageData.amount_due.toFixed(2)}`}
          </h2>
          <p style={styles.subtext}>Next invoice: {usageData.period_end}</p>
        </div>
      </div>

      <button 
        onClick={() => fetchUsage(true)} 
        disabled={isLoading} 
        style={{...styles.button, opacity: isLoading ? 0.5 : 1}}
      >
        {isLoading ? 'Syncing...' : 'Refresh Data'}
      </button>
    </div>
  );
};

const styles = {
  container: { padding: '40px', backgroundColor: '#f6f9fc', minHeight: '100vh', fontFamily: 'Inter, system-ui' },
  header: { marginBottom: '40px' },
  errorBanner: { padding: '12px', backgroundColor: '#fee2e2', color: '#b91c1c', borderRadius: '8px', marginBottom: '20px', fontSize: '14px' },
  grid: { display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: '20px' },
  card: { backgroundColor: '#fff', padding: '24px', borderRadius: '12px', boxShadow: '0 4px 6px rgba(50,50,93,.11)' },
  cardHeader: { display: 'flex', alignItems: 'center', gap: '10px', color: '#6b7280', marginBottom: '16px' },
  stat: { fontSize: '36px', margin: '0', color: '#1a1f36' },
  subtext: { color: '#6b7280', marginTop: '8px' },
  button: { marginTop: '24px', padding: '10px 20px', backgroundColor: '#635bff', color: '#fff', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: '600' }
};

export default App;