import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Zap, Home, Key, BookOpen, LogOut } from 'lucide-react';

const Sidebar = ({ onLogout }) => {
  const navigate = useNavigate();
  const location = useLocation();

  const menuItems = [
    { path: '/dashboard', label: 'Dashboard', icon: Home },
    { path: '/api-keys', label: 'API Keys', icon: Key },
    { path: '/endpoints', label: 'Endpoints', icon: BookOpen },
  ];

  return (
    <div style={styles.sidebar}>
      <div style={styles.logo}>
        <Zap size={32} color="#4f46e5" />
        <h2 style={styles.title}>API Marketplace</h2>
      </div>

      <nav style={styles.nav}>
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          return (
            <div
              key={item.path}
              onClick={() => navigate(item.path)}
              style={{
                ...styles.navItem,
                backgroundColor: isActive ? '#e0e7ff' : 'transparent',
                color: isActive ? '#4f46e5' : '#374151',
              }}
            >
              <Icon size={20} />
              <span>{item.label}</span>
            </div>
          );
        })}
      </nav>

      <div style={styles.bottom}>
        <button onClick={onLogout} style={styles.logoutBtn}>
          <LogOut size={18} /> Logout
        </button>
      </div>
    </div>
  );
};

const styles = {
  sidebar: {
    width: '260px',
    backgroundColor: '#ffffff',
    borderRight: '1px solid #e5e7eb',
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    position: 'sticky',
    top: 0,
  },
  logo: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '0 24px',
    marginBottom: '40px',
  },
  title: {
    margin: 0,
    fontSize: '22px',
    fontWeight: '700',
    color: '#1f2937',
  },
  nav: {
    flex: 1,
  },
  navItem: {
    display: 'flex',
    alignItems: 'center',
    gap: '12px',
    padding: '14px 24px',
    margin: '4px 12px',
    borderRadius: '10px',
    cursor: 'pointer',
    fontSize: '15px',
    fontWeight: '500',
    transition: 'all 0.2s',
  },
  bottom: {
    padding: '24px',
    marginTop: 'auto',
    borderTop: '1px solid #e5e7eb',
  },
  logoutBtn: {
    width: '100%',
    padding: '12px',
    backgroundColor: '#f3f4f6',
    border: 'none',
    borderRadius: '8px',
    color: '#374151',
    fontSize: '14px',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: '8px',
    cursor: 'pointer',
  },
};

export default Sidebar;