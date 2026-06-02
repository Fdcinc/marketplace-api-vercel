import React, { useState, useEffect } from 'react';

const API_BASE_URL = 'http://localhost:5000';

const Endpoints = ({ token }) => {
  const [usageData, setUsageData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch usage data (total hits, etc.)
  useEffect(() => {
    const fetchUsage = async () => {
      if (!token) {
        setError("No token found. Please login.");
        setLoading(false);
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

        if (!response.ok) throw new Error('Failed to fetch usage data');

        const json = await response.json();
        if (json.success) {
          setUsageData(json.data);
        } else {
          setError(json.error || 'Failed to load data');
        }
      } catch (err) {
        console.error(err);
        setError('Could not connect to backend. Is it running?');
      } finally {
        setLoading(false);
      }
    };

    fetchUsage();
  }, [token]);

  const endpoints = [
    { method: 'POST', path: '/api/v1/auth/register', desc: 'Register a new user' },
    { method: 'POST', path: '/api/v1/auth/login', desc: 'Login user and receive JWT token' },
    { method: 'POST', path: '/api/v1/auth/logout', desc: 'Logout user' },
    { method: 'GET', path: '/api/v1/auth/me', desc: 'Get current user profile' },
    { method: 'GET', path: '/api/v1/auth/usage', desc: 'Get current usage and billing info' },
    { method: 'GET', path: '/api/v1/auth/data', desc: 'Protected sample data endpoint' },
    { method: 'PATCH', path: '/api/v1/auth/update-me', desc: 'Update current user' },
    { method: 'DELETE', path: '/api/v1/auth/delete-me', desc: 'Delete current user' },
  ];

  return (
    <div>
      <h1 style={{ marginBottom: '8px' }}>API Endpoints</h1>
      <p style={{ color: '#6b7280', marginBottom: '24px' }}>
        Live endpoints from your Node.js backend
      </p>

      {/* Usage Stats Section */}
      <div style={styles.statsContainer}>
        <h3>Total API Hits (All Time)</h3>
        {loading ? (
          <p>Loading usage data...</p>
        ) : error ? (
          <p style={{ color: 'red' }}>{error}</p>
        ) : (
          <h2 style={styles.totalHits}>
            {usageData?.quantity ? usageData.quantity.toLocaleString() : '0'}
          </h2>
        )}
        <p style={{ color: '#6b7280' }}>Total requests made through this account</p>
      </div>

      {/* Endpoints List */}
      <div style={styles.list}>
        {endpoints.map((ep, index) => (
          <div key={index} style={styles.endpointCard}>
            <span style={{
              ...styles.method,
              backgroundColor: getMethodColor(ep.method)
            }}>
              {ep.method}
            </span>
            <span style={styles.path}>{ep.path}</span>
            <span style={styles.description}>{ep.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const getMethodColor = (method) => {
  switch (method) {
    case 'GET': return '#10b981';
    case 'POST': return '#3b82f6';
    case 'PATCH': return '#f59e0b';
    case 'DELETE': return '#ef4444';
    default: return '#6b7280';
  }
};

const styles = {
  statsContainer: {
    backgroundColor: '#ffffff',
    padding: '24px',
    borderRadius: '12px',
    border: '1px solid #e5e7eb',
    marginBottom: '32px',
  },
  totalHits: {
    fontSize: '48px',
    fontWeight: '700',
    color: '#1f2937',
    margin: '8px 0',
  },
  list: {
    display: 'flex',
    flexDirection: 'column',
    gap: '12px',
  },
  endpointCard: {
    backgroundColor: '#ffffff',
    padding: '20px',
    borderRadius: '12px',
    border: '1px solid #e5e7eb',
    display: 'grid',
    gridTemplateColumns: '90px 1fr 2fr',
    gap: '20px',
    alignItems: 'center',
  },
  method: {
    fontWeight: '700',
    padding: '6px 12px',
    borderRadius: '6px',
    textAlign: 'center',
    fontSize: '14px',
    color: 'white',
    width: 'fit-content',
  },
  path: {
    fontFamily: 'monospace',
    fontWeight: '500',
    color: '#1f2937',
  },
  description: {
    color: '#6b7280',
    fontSize: '15px',
  },
};

export default Endpoints;