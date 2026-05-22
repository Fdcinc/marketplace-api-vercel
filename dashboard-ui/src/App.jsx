import React, { useState, useEffect } from 'react';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';

const App = () => {
  const [token, setToken] = useState(localStorage.getItem('token'));

  // Sync with localStorage in case it changes
  useEffect(() => {
    const handleStorageChange = () => {
      setToken(localStorage.getItem('token'));
    };

    window.addEventListener('storage', handleStorageChange);
    return () => window.removeEventListener('storage', handleStorageChange);
  }, []);

  const handleLoginSuccess = (newToken) => {
    localStorage.setItem('token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setToken(null);
  };

  return (
    <>
      {!token ? (
        <Login onLoginSuccess={handleLoginSuccess} />
      ) : (
        <Dashboard token={token} onLogout={handleLogout} />
      )}
    </>
  );
};

export default App;