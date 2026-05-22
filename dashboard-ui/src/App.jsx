import React, { useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth0 } from '@auth0/auth0-react';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';
import ApiKeys from './pages/ApiKeys';
import Endpoints from './pages/Endpoints';
import Sidebar from './components/Sidebar';

const App = () => {
  const { isAuthenticated: isAuth0Authenticated, logout } = useAuth0();
  const [customToken, setCustomToken] = useState(localStorage.getItem('token'));

  const handleCustomLoginSuccess = (token) => {
    localStorage.setItem('token', token);
    setCustomToken(token);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    setCustomToken(null);

    if (isAuth0Authenticated) {
      logout({ returnTo: window.location.origin });
    } else {
      window.location.reload();
    }
  };

  const isLoggedIn = isAuth0Authenticated || !!customToken;

  return (
    <Router>
      {!isLoggedIn ? (
        <Login onCustomLoginSuccess={handleCustomLoginSuccess} />
      ) : (
        <div style={styles.appContainer}>
          <Sidebar onLogout={handleLogout} />
          
          <div style={styles.mainContent}>
            <Routes>
              <Route path="/dashboard" element={<Dashboard token={customToken} />} />
              <Route path="/api-keys" element={<ApiKeys />} />
              <Route path="/endpoints" element={<Endpoints />} />
              <Route path="*" element={<Navigate to="/dashboard" />} />
            </Routes>
          </div>
        </div>
      )}
    </Router>
  );
};

const styles = {
  appContainer: {
    display: 'flex',
    minHeight: '100vh',
    background: '#f8fafc',
    fontFamily: 'Inter, system-ui, sans-serif',
  },
  mainContent: {
    flex: 1,
    padding: '32px',
    overflow: 'auto',
  },
};

export default App;