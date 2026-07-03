import { useState } from 'react';

export const BillingChat = ({ token }) => {
  const [messages, setMessages] = useState([]);
  const [input, setInput] = useState('');

  const sendMessage = async () => {
    const newMessages = [...messages, { role: 'user', content: input }];
    setMessages(newMessages);

    const res = await fetch('http://localhost:5000/api/v1/agent/chat', {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}` 
      },
      body: JSON.stringify({ message: input })
    });
    
    const data = await res.json();
    setMessages([...newMessages, { role: 'assistant', content: data.response }]);
    setInput('');
  };

  return (
    <div style={{ backgroundColor: '#ffffff', padding: '32px', borderRadius: '16px', border: '1px solid #e5e7eb', boxShadow: '0 4px 6px -1px rgba(0,0,0,0.1)' }}>
      <h3 style={{ marginBottom: '20px', color: '#1f2937' }}>Billing AI Assistant</h3>
      <div style={{ height: '200px', overflowY: 'auto', marginBottom: '20px', padding: '10px', backgroundColor: '#f9fafb', borderRadius: '8px' }}>
        {messages.map((m, i) => (
          <p key={i} style={{ margin: '5px 0', fontSize: '14px' }}>
            <strong>{m.role === 'user' ? 'You' : 'AI'}:</strong> {m.content}
          </p>
        ))}
      </div>
      <div style={{ display: 'flex', gap: '10px' }}>
        <input 
          style={{ flex: 1, padding: '10px', borderRadius: '8px', border: '1px solid #d1d5db' }}
          value={input} 
          onChange={(e) => setInput(e.target.value)} 
          placeholder="Ask about your credits..."
        />
        <button 
          style={{ padding: '10px 20px', backgroundColor: '#4f46e5', color: 'white', border: 'none', borderRadius: '8px', cursor: 'pointer' }}
          onClick={sendMessage}
        >
          Send
        </button>
      </div>
    </div>
  );
};