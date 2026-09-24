import React, { useState, useCallback, useEffect } from 'react';
import {
  CreditCard,
  Wallet,
  ExternalLink,
  RefreshCw,
  Zap,
  ArrowRightCircle,
} from 'lucide-react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

/**
 * Billing page – credit balance + Stripe actions + early trial switch.
 */
const Billing = ({ token }) => {
  const [usageData, setUsageData] = useState({
    credits: 0,
    isTrial: true,
    trialRemaining: 0,
    trialLimit: 1000,
    quantity: 0,
    amount_due: 0,
    period_end: '--',
    currency: 'EUR',
  });
  const [loading, setLoading] = useState(true);
  const [actionLoading, setActionLoading] = useState(null); // 'checkout' | 'portal' | 'switch' | null
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const packs = [
    { credits: 1000, amount: 1000, label: '1,000 credits', price: '$10' },
    { credits: 5000, amount: 4000, label: '5,000 credits', price: '$40' },
    { credits: 10000, amount: 7000, label: '10,000 credits', price: '$70' },
  ];

  const getHeaders = useCallback(() => {
    const authType = localStorage.getItem('auth_type');
    const headers = {
      Authorization: `Bearer ${token}`,
      'x-platform-secret': 'my-marketplace-private-key-123',
      'Content-Type': 'application/json',
    };
    if (authType === 'auth0') {
      headers['x-auth-source'] = 'auth0';
    }
    return headers;
  }, [token]);

  const fetchUsage = useCallback(
    async (showLoading = true) => {
      if (!token) {
        setError('No authentication token found. Please login again.');
        setLoading(false);
        return;
      }
      if (showLoading) setLoading(true);
      setError(null);

      try {
        const response = await fetch(`${API_BASE_URL}/api/v1/auth/usage`, {
          method: 'GET',
          headers: getHeaders(),
        });

        if (response.status === 401) {
          throw new Error('Unauthorized: Please check your login session.');
        }
        if (!response.ok) throw new Error(`Server error: ${response.status}`);

        const json = await response.json();
        if (json.success) {
          setUsageData({
            credits: json.data.credits ?? 0,
            isTrial: json.data.isTrial ?? false,
            trialRemaining: json.data.trialRemaining ?? 0,
            trialLimit: json.data.trialLimit ?? 1000,
            quantity: json.data.quantity ?? 0,
            amount_due: json.data.amount_due ?? 0,
            period_end: json.data.period_end ?? '--',
            currency: json.data.currency ?? 'EUR',
          });
        } else {
          setError(json.error || 'Failed to load billing data');
        }
      } catch (err) {
        setError(err.message || 'Could not connect to backend.');
      } finally {
        setLoading(false);
      }
    },
    [token, getHeaders]
  );

  useEffect(() => {
    const timer = setTimeout(() => fetchUsage(true), 300);
    return () => clearTimeout(timer);
  }, [fetchUsage]);

  // Fixed: Wrapped URL parameter state updates safely to prevent cascading render warnings
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('billing_success') === 'true') {
      const timer = setTimeout(() => {
        setSuccessMsg('Payment successful! Credits will appear shortly.');
        fetchUsage(false);
        window.history.replaceState({}, '', window.location.pathname);
      }, 0);
      return () => clearTimeout(timer);
    } else if (params.get('billing_canceled') === 'true') {
      const timer = setTimeout(() => {
        setError('Checkout was canceled.');
        window.history.replaceState({}, '', window.location.pathname);
      }, 0);
      return () => clearTimeout(timer);
    }
  }, [fetchUsage]);

  const buyPack = async (pack) => {
    setActionLoading('checkout');
    setError(null);
    setSuccessMsg(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/billing/create-checkout-session`,
        {
          method: 'POST',
          headers: getHeaders(),
          body: JSON.stringify({
            credits: pack.credits,
            amount: pack.amount,
            name: `API Credit Pack (${pack.label})`,
          }),
        }
      );
      const json = await response.json();
      if (json.success && json.url) {
        // Fixed: Assign to location target safely using assignment wrapper
        window.location.assign(json.url);
      } else {
        setError(json.error || 'Failed to start checkout');
      }
    } catch (err) {
      setError(err.message || 'Checkout request failed');
    } finally {
      setActionLoading(null);
    }
  };

  const openPortal = async () => {
    setActionLoading('portal');
    setError(null);
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/billing/create-portal-session`,
        {
          method: 'POST',
          headers: getHeaders(),
        }
      );
      const json = await response.json();
      if (json.success && json.url) {
        window.location.assign(json.url);
      } else {
        setError(json.error || 'Failed to open billing portal');
      }
    } catch (err) {
      setError(err.message || 'Portal request failed');
    } finally {
      setActionLoading(null);
    }
  };

  const switchToCredits = async () => {
    const remaining = usageData.trialRemaining || 0;
    const confirmMsg =
      remaining > 0
        ? `End trial now?\n\nYour ${remaining.toLocaleString()} remaining trial requests will be added to your credit balance. After this you will use credits only.`
        : 'End trial now and switch to credit balance?';

    if (!window.confirm(confirmMsg)) return;

    setActionLoading('switch');
    setError(null);
    setSuccessMsg(null);

    try {
      const response = await fetch(
        `${API_BASE_URL}/api/v1/billing/switch-to-credits`,
        {
          method: 'POST',
          headers: getHeaders(),
        }
      );

      const raw = await response.text();
      let json;
      try {
        json = JSON.parse(raw);
      } catch {
        // HTML/404 from Express or Vite when the route is missing
        setError(
          `Switch failed (${response.status}). Backend route missing or wrong server. ` +
            `Expected POST ${API_BASE_URL}/api/v1/billing/switch-to-credits to return JSON. ` +
            `Copy billing.js + billingController.js and restart the API.`
        );
        return;
      }

      if (!response.ok || !json.success) {
        setError(json.error || `Failed to switch to credits (${response.status})`);
        return;
      }

      setSuccessMsg(json.message);
      await fetchUsage(false);
    } catch (err) {
      setError(err.message || 'Switch request failed');
    } finally {
      setActionLoading(null);
    }
  };

  const isOnCredits = !usageData.isTrial || usageData.trialRemaining <= 0;
  const stillOnTrial = usageData.isTrial && usageData.trialRemaining > 0;

  return (
    <div>
      <div style={styles.header}>
        <div>
          <h1 style={styles.pageTitle}>Billing</h1>
          <p style={styles.subtitle}>
            Manage credits, trial status, and payment methods
          </p>
        </div>
        <button
          onClick={() => fetchUsage(true)}
          disabled={loading}
          style={styles.refreshBtn}
        >
          <RefreshCw size={16} />
          {loading ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {error && <div style={styles.errorBanner}>{error}</div>}
      {successMsg && <div style={styles.successBanner}>{successMsg}</div>}

      <div style={styles.balanceCard}>
        <div style={styles.balanceHeader}>
          <Wallet size={28} color="#4f46e5" />
          <span style={styles.balanceLabel}>
            {isOnCredits ? 'Credit Balance' : 'Trial Status'}
          </span>
        </div>

        {loading ? (
          <h2 style={styles.balanceStat}>…</h2>
        ) : isOnCredits ? (
          <>
            <h2 style={styles.balanceStat}>
              {(usageData.credits || 0).toLocaleString()}
            </h2>
            <p style={styles.subtext}>API requests remaining</p>
            {usageData.credits <= 0 && (
              <p style={styles.warning}>
                You have no credits left. Purchase a pack below to continue.
              </p>
            )}
          </>
        ) : (
          <>
            <h2 style={styles.balanceStat}>
              {usageData.trialRemaining.toLocaleString()}
            </h2>
            <p style={styles.subtext}>
              Trial requests remaining of{' '}
              {usageData.trialLimit.toLocaleString()}
            </p>
            <div style={styles.progressContainer}>
              <div
                style={{
                  ...styles.progressBar,
                  width: `${Math.min(
                    100,
                    ((usageData.trialLimit - usageData.trialRemaining) /
                      usageData.trialLimit) *
                      100
                  )}%`,
                }}
              />
            </div>
            <p style={{ ...styles.subtext, marginTop: 12 }}>
              After trial ends you will automatically switch to your credit
              balance. You can also switch early below.
            </p>
          </>
        )}
      </div>

      {stillOnTrial && (
        <div style={styles.switchCard}>
          <div style={{ flex: 1 }}>
            <h3 style={styles.switchTitle}>
              <ArrowRightCircle size={20} color="#4f46e5" />
              Switch to credit balance early
            </h3>
            <p style={styles.subtext}>
              End your trial now. Your{' '}
              <strong>{usageData.trialRemaining.toLocaleString()}</strong>{' '}
              remaining trial requests will be added to your credit balance so
              you don’t lose them. Future API usage will draw from credits.
            </p>
          </div>
          <button
            onClick={switchToCredits}
            disabled={!!actionLoading}
            style={styles.switchBtn}
          >
            {actionLoading === 'switch'
              ? 'Switching…'
              : 'End trial & switch to credits'}
          </button>
        </div>
      )}

      <div style={styles.grid}>
        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <Zap size={20} color="#f59e0b" />
            <span>Usage this cycle</span>
          </div>
          <h3 style={styles.statSmall}>
            {loading ? '…' : (usageData.quantity || 0).toLocaleString()}
          </h3>
          <p style={styles.subtext}>Total metered requests</p>
        </div>

        <div style={styles.card}>
          <div style={styles.cardHeader}>
            <CreditCard size={20} color="#10b981" />
            <span>Next invoice</span>
          </div>
          <h3 style={styles.statSmall}>
            {loading
              ? '…'
              : `${usageData.currency === 'EUR' ? '€' : '$'}${(
                  usageData.amount_due || 0
                ).toFixed(2)}`}
          </h3>
          <p style={styles.subtext}>Due: {usageData.period_end}</p>
        </div>
      </div>

      <h2 style={styles.sectionTitle}>Buy Credit Packs</h2>
      <p style={styles.sectionDesc}>
        One-time purchases. Credits are added instantly after successful
        payment.
      </p>

      <div style={styles.packsGrid}>
        {packs.map((pack) => (
          <div key={pack.credits} style={styles.packCard}>
            <h3 style={styles.packLabel}>{pack.label}</h3>
            <p style={styles.packPrice}>{pack.price}</p>
            <button
              onClick={() => buyPack(pack)}
              disabled={!!actionLoading}
              style={styles.buyBtn}
            >
              {actionLoading === 'checkout' ? 'Redirecting…' : 'Buy now'}
            </button>
          </div>
        ))}
      </div>

      <div style={styles.portalSection}>
        <div>
          <h3 style={{ margin: '0 0 4px 0' }}>Payment methods & invoices</h3>
          <p style={styles.subtext}>
            Update cards, view past invoices, or cancel in the Stripe customer
            portal.
          </p>
        </div>
        <button
          onClick={openPortal}
          disabled={!!actionLoading}
          style={styles.portalBtn}
        >
          <ExternalLink size={16} />
          {actionLoading === 'portal' ? 'Opening…' : 'Open Billing Portal'}
        </button>
      </div>
    </div>
  );
};

const styles = {
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 32,
  },
  pageTitle: {
    fontSize: 32,
    fontWeight: 700,
    color: '#1f2937',
    margin: '0 0 8px 0',
  },
  subtitle: { color: '#6b7280', fontSize: 16, margin: 0 },
  refreshBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '10px 16px',
    backgroundColor: '#f3f4f6',
    border: '1px solid #e5e7eb',
    borderRadius: 8,
    cursor: 'pointer',
    fontSize: 14,
    fontWeight: 500,
  },
  errorBanner: {
    backgroundColor: '#fef2f2',
    color: '#dc2626',
    padding: '14px 20px',
    borderRadius: 10,
    marginBottom: 24,
    border: '1px solid #fecaca',
  },
  successBanner: {
    backgroundColor: '#ecfdf5',
    color: '#059669',
    padding: '14px 20px',
    borderRadius: 10,
    marginBottom: 24,
    border: '1px solid #a7f3d0',
  },
  balanceCard: {
    backgroundColor: '#ffffff',
    padding: 36,
    borderRadius: 16,
    border: '1px solid #e5e7eb',
    boxShadow: '0 4px 6px -1px rgba(0,0,0,0.08)',
    marginBottom: 20,
  },
  balanceHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: 12,
    marginBottom: 16,
    color: '#4b5563',
    fontWeight: 600,
  },
  balanceLabel: { fontSize: 16 },
  balanceStat: {
    margin: '0 0 8px 0',
    fontSize: 52,
    fontWeight: 700,
    color: '#1f2937',
  },
  subtext: { color: '#6b7280', margin: 0, fontSize: 15 },
  warning: {
    marginTop: 12,
    color: '#dc2626',
    fontWeight: 500,
    fontSize: 14,
  },
  progressContainer: {
    width: '100%',
    backgroundColor: '#e5e7eb',
    borderRadius: 10,
    height: 10,
    marginTop: 16,
    overflow: 'hidden',
  },
  progressBar: {
    backgroundColor: '#f59e0b',
    height: '100%',
    transition: 'width 0.5s ease-in-out',
  },
  switchCard: {
    display: 'flex',
    alignItems: 'center',
    gap: 24,
    backgroundColor: '#eef2ff',
    border: '1px solid #c7d2fe',
    borderRadius: 14,
    padding: 24,
    marginBottom: 28,
    flexWrap: 'wrap',
  },
  switchTitle: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    margin: '0 0 8px 0',
    fontSize: 17,
    fontWeight: 600,
    color: '#1f2937',
  },
  switchBtn: {
    padding: '12px 20px',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: 10,
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: 14,
    whiteSpace: 'nowrap',
  },
  grid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))',
    gap: 20,
    marginBottom: 40,
  },
  card: {
    backgroundColor: '#ffffff',
    padding: 24,
    borderRadius: 14,
    border: '1px solid #e5e7eb',
  },
  cardHeader: {
    display: 'flex',
    alignItems: 'center',
    gap: 10,
    marginBottom: 12,
    color: '#4b5563',
    fontWeight: 600,
    fontSize: 14,
  },
  statSmall: {
    margin: '0 0 4px 0',
    fontSize: 28,
    fontWeight: 700,
    color: '#1f2937',
  },
  sectionTitle: {
    fontSize: 22,
    fontWeight: 700,
    color: '#1f2937',
    margin: '0 0 6px 0',
  },
  sectionDesc: { color: '#6b7280', marginBottom: 20, fontSize: 15 },
  packsGrid: {
    display: 'grid',
    gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
    gap: 16,
    marginBottom: 40,
  },
  packCard: {
    backgroundColor: '#ffffff',
    padding: 24,
    borderRadius: 14,
    border: '1px solid #e5e7eb',
    textAlign: 'center',
  },
  packLabel: { margin: '0 0 8px 0', fontSize: 18, fontWeight: 600 },
  packPrice: {
    margin: '0 0 16px 0',
    fontSize: 28,
    fontWeight: 700,
    color: '#4f46e5',
  },
  buyBtn: {
    width: '100%',
    padding: '12px 16px',
    backgroundColor: '#4f46e5',
    color: 'white',
    border: 'none',
    borderRadius: 10,
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: 15,
  },
  portalSection: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    backgroundColor: '#f9fafb',
    padding: 24,
    borderRadius: 14,
    border: '1px solid #e5e7eb',
    flexWrap: 'wrap',
    gap: 16,
  },
  portalBtn: {
    display: 'flex',
    alignItems: 'center',
    gap: 8,
    padding: '12px 20px',
    backgroundColor: '#1f2937',
    color: 'white',
    border: 'none',
    borderRadius: 10,
    fontWeight: 600,
    cursor: 'pointer',
    fontSize: 14,
  },
};

export default Billing;
