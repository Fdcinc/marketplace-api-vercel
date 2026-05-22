import React from 'react';

const Endpoints = () => {
  const endpoints = [
    { method: 'POST', path: '/api/v1/auth/login', desc: 'Authenticate with email and password' },
    { method: 'GET', path: '/api/v1/auth/usage', desc: 'Get current usage and billing information' },
    { method: 'GET', path: '/api/v1/models', desc: 'List all available AI models' },
    { method: 'POST', path: '/api/v1/completions', desc: 'Generate text completion' },
    { method: 'POST', path: '/api/v1/chat', desc: 'Chat completions (conversational)' },
  ];

  return (
    <div>
      <h1 style={{ marginBottom: '8px' }}>API Endpoints</h1>
      <p style={{ color: '#6b7280', marginBottom: '32px' }}>
        Available endpoints in the API Marketplace
      </p>

      <div style={styles.list}>
        {endpoints.map((ep, index) => (
          <div key={index} style={styles.endpointCard}>
            <span style={styles.method}>{ep.method}</span>
            <span style={styles.path}>{ep.path}</span>
            <span style={styles.description}>{ep.desc}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const styles = {
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
    color: '#10b981',
    fontSize: '15px',
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