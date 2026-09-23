import { useState } from 'react';

const API_BASE_URL = 'http://localhost:5000';

export const BillingChat = ({ token }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');
  const [sending, setSending] = useState(false);

  const sendMessage = async () => {
    if (!input.trim() || sending) return;

    const newMessages = [...messages, { role: 'user', content: input }];
    setMessages(newMessages);
    setInput('');
    setSending(true);

    try {
      const authType = localStorage.getItem('auth_type');
      const headers = {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      };
      if (authType === 'auth0') {
        headers['x-auth-source'] = 'auth0';
      }

      const res = await fetch(`${API_BASE_URL}/api/v1/agent/chat`, {
        method: 'POST',
        headers,
        body: JSON.stringify({ message: input }),
      });

      const data = await res.json();
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          content: data.response || data.error || 'No response from assistant.',
        },
      ]);
    } catch {
      setMessages([
        ...newMessages,
        {
          role: 'assistant',
          content: 'Failed to reach the billing assistant. Is the backend running?',
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  return (
    <div
      style={{
        backgroundColor: '#ffffff',
        padding: '32px',
        borderRadius: '16px',
        border: '1px solid #e5e7eb',
        boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)',
      }}
    >
      <h3 style={{ marginBottom: '20px', color: '#1f2937' }}>
        Billing AI Assistant
      </h3>
      <div
        style={{
          height: '200px',
          overflowY: 'auto',
          marginBottom: '20px',
          padding: '10px',
          backgroundColor: '#f9fafb',
          borderRadius: '8px',
        }}
      >
        {messages.length === 0 && (
          <p style={{ color: '#9ca3af', fontSize: 14 }}>
            Ask about your credits, trial status, or how to top up…
          </p>
        )}
        {messages.map((m, i) => (
          <p key={i} style={{ margin: '5px 0', fontSize: '14px' }}>
            <strong>{m.role === 'user' ? 'You' : 'AI'}:</strong> {m.content}
          </p>
        ))}
      </div>
      <div style={{ display: 'flex', gap: '10px' }}>
        <input
          style={{
            flex: 1,
            padding: '10px',
            borderRadius: '8px',
            border: '1px solid #d1d5db',
          }}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && sendMessage()}
          placeholder="Ask about your credits..."
          disabled={sending}
        />
        <button
          style={{
            padding: '10px 20px',
            backgroundColor: '#4f46e5',
            color: 'white',
            border: 'none',
            borderRadius: '8px',
            cursor: 'pointer',
          }}
          onClick={sendMessage}
          disabled={sending}
        >
          {sending ? '…' : 'Send'}
        </button>
      </div>
    </div>
  );
};
