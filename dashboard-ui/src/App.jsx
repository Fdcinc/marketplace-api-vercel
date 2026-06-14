import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { useAuth0 } from '@auth0/auth0-react';
import Login from './components/Login';
import Dashboard from './pages/Dashboard';
import ApiKeys from './pages/ApiKeys';
import Endpoints from './pages/Endpoints';
import Sidebar from './components/Sidebar';

const App = () => {
  const { 
    isAuthenticated: isAuth0Authenticated, 
    logout, 
    getAccessTokenSilently,
    isLoading 
  } = useAuth0();
  
  const [customToken, setCustomToken] = useState(localStorage.getItem('token'));
  const [auth0Token, setAuth0Token] = useState(null);

  // Fetch Auth0 token when authenticated
  useEffect(() => {
    const fetchAuth0Token = async () => {
      if (isAuth0Authenticated) {
        try {
          const token = await getAccessTokenSilently({
            authorizationParams: {
              audience: import.meta.env.VITE_AUTH0_AUDIENCE,
            }
          });
          setAuth0Token(token);
          localStorage.setItem('auth_type', 'auth0');
        } catch (e) {
          console.error("Auth0 token fetch failed:", e);
        }
      }
    };
    fetchAuth0Token();
  }, [isAuth0Authenticated, getAccessTokenSilently]);

  const handleCustomLoginSuccess = (token) => {
    localStorage.setItem('token', token);
    localStorage.setItem('auth_type', 'local');
    setCustomToken(token);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('auth_type');
    setCustomToken(null);
    setAuth0Token(null);

    if (isAuth0Authenticated) {
      logout({ logoutParams: { returnTo: window.location.origin } });
    } else {
      window.location.reload();
    }
  };

  if (isLoading) return <div>Loading...</div>;

  const isLoggedIn = isAuth0Authenticated || !!customToken;
  const activeToken = auth0Token || customToken;

  return (
    <Router>
      {!isLoggedIn ? (
        <Login onCustomLoginSuccess={handleCustomLoginSuccess} />
      ) : (
        <div style={styles.appContainer}>
          <Sidebar onLogout={handleLogout} />
          
          <div style={styles.mainContent}>
            <Routes>
              {/* Pass activeToken instead of customToken */}
              <Route path="/dashboard" element={<Dashboard token={activeToken} />} />
              <Route path="/api-keys" element={<ApiKeys />} />
              <Route path="/endpoints" element={<Endpoints token={activeToken} />} />
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
    fontFamily: 'Inter, system-ui, sans-serif',
  },
  mainContent: {
    flex: 1,
    padding: '32px',
    overflow: 'auto',
  },
};

export default App;