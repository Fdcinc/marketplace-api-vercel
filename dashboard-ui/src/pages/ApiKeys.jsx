import React, { useState } from 'react';
import { Copy, Plus, Trash2 } from 'lucide-react';

const ApiKeys = () => {
  const [keys, setKeys] = useState([
    {
      id: 1,
      name: 'Production Key',
      key: 'ak_live_8f3k9x2m7p4q9v2n',
      created: '2025-05-10',
    },
    {
      id: 2,
      name: 'Development Key',
      key: 'ak_test_9p2m7q8v4l3x6t1r',
      created: '2025-05-15',
    },
  ]);

  const copyToClipboard = (key) => {
    navigator.clipboard.writeText(key);
    alert('API Key copied to clipboard!');
  };

  const generateNewKey = () => {
    const newKey = {
      id: Date.now(),
      name: 'New API Key',
      key: `ak_live_${Math.random().toString(36).substring(2, 18)}`,
      created: new Date().toISOString().split('T')[0],
    };
    setKeys([...keys, newKey]);
  };

  const deleteKey = (id) => {
    if (window.confirm('Delete this API key?')) {
      setKeys(keys.filter(key => key.id !== id));
    }
  };

  return (
    <div>
      <h1 style={{ marginBottom: '8px' }}>API Keys</h1>
      <p style={{ color: '#6b7280', marginBottom: '32px' }}>
        Manage and create API keys for accessing the marketplace
      </p>

      <button onClick={generateNewKey} style={styles.addButton}>
        <Plus size={18} /> Generate New API Key
      </button>

      <div style={styles.keysList}>
        {keys.map((item) => (
          <div key={item.id} style={styles.keyCard}>
            <div style={styles.keyInfo}>
              <h4 style={styles.keyName}>{item.name}</h4>
              <p style={styles.keyValue}>{item.key}</p>
              <small style={styles.date}>Created: {item.created}</small>
            </div>

            <div style={styles.actions}>
              <button onClick={() => copyToClipboard(item.key)} style={styles.copyBtn}>
                <Copy size={18} />
              </button>
              <button onClick={() => deleteKey(item.id)} style={styles.deleteBtn}>
                <Trash2 size={18} />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

const styles = {
  addButton: {
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    padding: '12px 20px',
    borderRadius: '10px',
    display: 'flex',
    alignItems: 'center',
    gap: '8px',
    fontWeight: '600',
    cursor: 'pointer',
    marginBottom: '24px',
  },
  keysList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '16px',
  },
  keyCard: {
    backgroundColor: '#fff',
    padding: '20px',
    borderRadius: '12px',
    border: '1px solid #e5e7eb',
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
  },
  keyInfo: {
    flex: 1,
  },
  keyName: {
    margin: '0 0 6px 0',
    fontSize: '16px',
  },
  keyValue: {
    fontFamily: 'monospace',
    color: '#374151',
    margin: '6px 0',
    fontSize: '15px',
  },
  date: {
    color: '#6b7280',
    fontSize: '13px',
  },
  actions: {
    display: 'flex',
    gap: '8px',
  },
  copyBtn: {
    padding: '8px',
    background: '#f3f4f6',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    cursor: 'pointer',
  },
  deleteBtn: {
    padding: '8px',
    background: '#fee2e2',
    color: '#ef4444',
    border: '1px solid #fecaca',
    borderRadius: '6px',
    cursor: 'pointer',
  },
};

export default ApiKeys;