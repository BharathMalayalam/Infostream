import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../api/axios.js';
import ThemeToggle from '../components/ThemeToggle';

import useAuth from '../context/useAuth';

/* ─── Inline Toast (replaces window.alert) ─── */
function Toast({ message, type = 'success', onDismiss }) {
  useEffect(() => {
    const t = setTimeout(onDismiss, 4000);
    return () => clearTimeout(t);
  }, [onDismiss]);

  return (
    <div className={`inline-toast ${type}`}>
      <i className={`fas ${type === 'success' ? 'fa-check-circle' : 'fa-exclamation-circle'}`}></i>
      {message}
      <button
        onClick={onDismiss}
        style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'inherit', cursor: 'pointer', fontSize: 14, padding: 0 }}
      >
        <i className="fas fa-times"></i>
      </button>
    </div>
  );
}

function StudentDashboard() {
  const [streams, setStreams] = useState([]);
  const [filteredStreams, setFilteredStreams] = useState([]);
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({ type: 'all', category: 'all', date: 'all' });
  const [urgentAlerts, setUrgentAlerts] = useState([]);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [lastUrgentCheck, setLastUrgentCheck] = useState(new Date().toISOString());
  const [toast, setToast] = useState(null);
  const [activeTab, setActiveTab] = useState('streams-section'); // 'streams-section' or 'settings-section'
  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '' });

  const navigate = useNavigate();
  const { logout, user } = useAuth();

  const showToast = (message, type = 'success') => setToast({ message, type });
  const dismissToast = () => setToast(null);

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/change-password`, passwordForm);
      showToast('Password changed successfully!');
      setPasswordForm({ currentPassword: '', newPassword: '' });
      setActiveTab('streams-section');
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to change password.', 'error');
    }
  };

  /* ─── Data fetching ─── */
  const fetchStreams = useCallback(async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/student`);
      setStreams(res.data.streams);
      setFilteredStreams(res.data.streams);
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) navigate('/login');
    }
  }, [navigate]);

  // Use a ref to always hold the latest poll function — avoids stale closure in setInterval
  const pollRef = React.useRef(null);
  pollRef.current = async () => {
    try {
      const res = await axios.get(
        `${import.meta.env.VITE_API_URL}/api/auth/urgent_check?since=${encodeURIComponent(lastUrgentCheck)}`
      );
      if (res.data.urgent_alerts?.length > 0) {
        setUrgentAlerts((prev) => [...prev, ...res.data.urgent_alerts]);
        const maxTime = res.data.urgent_alerts.reduce(
          (max, a) => (new Date(a.created_at) > new Date(max) ? a.created_at : max),
          lastUrgentCheck
        );
        setLastUrgentCheck(maxTime);
      }
    } catch (err) {
      console.warn('Urgent check failed:', err?.message || err);
      // Silently ignore poll errors (network blip, session expired handled on fetch)
    }
  };

  useEffect(() => {
    fetchStreams();
    // Browser Notification permission request
    if (typeof Notification !== 'undefined' && Notification.permission === 'default') {
      Notification.requestPermission();
    }
    // Interval always calls the latest version of poll via ref — no stale closure
    const interval = setInterval(() => pollRef.current?.(), 10000);
    return () => clearInterval(interval);
  }, [fetchStreams]);

  /* ─── Filtering ─── */
  useEffect(() => {
    const today = new Date().toISOString().split('T')[0];
    const y = new Date();
    y.setDate(y.getDate() - 1);
    const yesterday = y.toISOString().split('T')[0];

    setFilteredStreams(
      streams.filter((s) => {
        const text = (s.title || s.company || s.content || s.description || '').toLowerCase();
        const dateStr = (s.created_at || '').split('T')[0];
        const matchSearch = text.includes(search.toLowerCase());
        const matchType = filters.type === 'all' || s.type === filters.type;
        const matchCat = filters.category === 'all' || s.category === filters.category;
        let matchDate = true;
        if (filters.date === 'today') matchDate = dateStr === today;
        if (filters.date === 'yesterday') matchDate = dateStr === yesterday;
        return matchSearch && matchType && matchCat && matchDate;
      })
    );
  }, [search, filters, streams]);

  const handleFilterChange = (key, value) => {
    if (key === 'type' && value === 'all') {
      setFilters({ type: 'all', category: 'all', date: 'all' });
    } else {
      setFilters((prev) => ({ ...prev, [key]: value }));
    }
    // Only close sidebar on mobile (< 768px) — desktop should not flicker/freeze
    if (window.innerWidth < 768) setSidebarOpen(false);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  const closeSidebar = () => setSidebarOpen(false);
  const hasUrgentVisible = filteredStreams.some((s) => s.is_urgent === 1);

  /* ─── Helpers ─── */
  const formatDate = (iso) => {
    const d = new Date(iso);
    return d.toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' });
  };

  const activeFilterCount = [
    filters.type !== 'all',
    filters.category !== 'all',
    filters.date !== 'all',
  ].filter(Boolean).length;

  return (
    <div className="page-full">
      {/* ── Navbar ── */}
      <nav className="dashboard-nav">
        <div className="nav-brand">
          <button
            className={`hamburger-btn ${sidebarOpen ? 'open' : ''}`}
            onClick={() => setSidebarOpen((o) => !o)}
            aria-label="Toggle sidebar"
          >
            <span></span>
            <span></span>
            <span></span>
          </button>
          <div className="nav-brand-icon">
            <i className="fas fa-signal"></i>
          </div>
          <span className="nav-brand-text">INFOSTREAM</span>
        </div>

        <div className="nav-actions">
          <ThemeToggle />
          <Link to="/" className="nav-btn nav-btn-home">
            <i className="fas fa-home"></i>
            <span>HOME</span>
          </Link>
          <button onClick={handleLogout} className="nav-btn nav-btn-logout">
            <i className="fas fa-power-off"></i>
            <span>LOGOUT</span>
          </button>
        </div>
      </nav>

      {/* ── Layout ── */}
      <div className="dashboard-layout">
        {/* Mobile overlay */}
        <div
          className={`sidebar-overlay ${sidebarOpen ? '' : 'hidden'}`}
          onClick={closeSidebar}
        />

        {/* ── Sidebar ── */}
        <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
          {/* Profile */}
          <div className="sidebar-profile">
            <div className="profile-avatar">
              <i className="fas fa-user-graduate"></i>
            </div>
            <div>
              <div className="profile-info-label">Logged In As</div>
              <div className="profile-info-value" style={{ textTransform: 'capitalize' }}>{user?.username}</div>
              <div style={{ fontSize: 10, color: 'var(--accent-warn)', fontWeight: 700, letterSpacing: '0.5px' }}>STUDENT</div>
            </div>
          </div>

          {/* Search */}
          <div className="search-wrapper" style={{ marginBottom: 16 }}>
            <i className="fas fa-search"></i>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search posts..."
            />
          </div>

          {/* Filter nav */}
          <nav>
            <button
              className={`nav-tab ${filters.type === 'all' && filters.category === 'all' && filters.date === 'all' ? 'active' : ''}`}
              onClick={() => handleFilterChange('type', 'all')}
            >
              <i className="fas fa-th-large"></i> ALL STREAMS
              {activeFilterCount > 0 && (
                <span className="badge badge-accent" style={{ marginLeft: 'auto', fontSize: 8 }}>
                  {activeFilterCount}
                </span>
              )}
            </button>

            <div className="sidebar-section-label">Category</div>

            {[
              { label: 'EXAM CELL',   icon: 'fa-file-invoice', val: 'Exam Cell'  },
              { label: 'PLACEMENTS',  icon: 'fa-briefcase',    val: 'Placement'  },
              { label: 'EVENTS',      icon: 'fa-calendar-alt', val: 'Events'     },
            ].map(({ label, icon, val }) => (
              <button
                key={val}
                className={`nav-tab ${filters.category === val ? 'active' : ''}`}
                onClick={() => handleFilterChange('category', val)}
              >
                <i className={`fas ${icon}`}></i> {label}
              </button>
            ))}

            <div className="sidebar-section-label">Timeline</div>

            {[
              { label: 'TODAY',     icon: 'fa-clock',   val: 'today'     },
              { label: 'YESTERDAY', icon: 'fa-history', val: 'yesterday' },
            ].map(({ label, icon, val }) => (
              <button
                key={val}
                className={`nav-tab ${filters.date === val ? 'active' : ''}`}
                onClick={() => handleFilterChange('date', val)}
              >
                <i className={`fas ${icon}`}></i> {label}
              </button>
            ))}
          </nav>

          {/* Settings button */}
          <div style={{ paddingTop: 8, borderTop: '1px solid var(--border)', marginTop: 8 }}>
            <button
              className={`nav-tab ${activeTab === 'settings-section' ? 'active' : ''}`}
              onClick={() => { setActiveTab('settings-section'); setSidebarOpen(false); }}
            >
              <i className="fas fa-cog"></i> SETTINGS
            </button>
          </div>

          {/* System status */}
          <div className="system-status">
            <div className="status-dot"></div>
            <span className="status-text">Operational &amp; Encrypted</span>
          </div>
        </aside>

        {/* ── Main Content ── */}
        <main className="dashboard-main">
          {/* Toast */}
          {toast && <Toast message={toast.message} type={toast.type} onDismiss={dismissToast} />}

          {/* ── SETTINGS TAB ── */}
          {activeTab === 'settings-section' && (
            <div className="glass-card" style={{ padding: '32px', maxWidth: '480px', margin: '0 auto' }}>
              <div className="section-header">
                <div className="section-icon" style={{ background: 'var(--accent)' }}>
                  <i className="fas fa-key" style={{ color: '#000' }}></i>
                </div>
                <h2 className="section-title">CHANGE PASSWORD</h2>
              </div>
              <p style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 24 }}>
                Logged in as <strong style={{ color: 'var(--accent)' }}>{user?.username}</strong>.
                Choose a strong new password.
              </p>
              <form onSubmit={handlePasswordChange}>
                <div className="form-group">
                  <label className="form-label">Current Password</label>
                  <div className="input-wrapper">
                    <i className="fas fa-lock input-icon"></i>
                    <input
                      type="password"
                      value={passwordForm.currentPassword}
                      onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                      placeholder="Enter current password"
                      required
                    />
                  </div>
                </div>
                <div className="form-group">
                  <label className="form-label">New Password</label>
                  <div className="input-wrapper">
                    <i className="fas fa-lock-open input-icon"></i>
                    <input
                      type="password"
                      value={passwordForm.newPassword}
                      onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                      placeholder="Enter new password"
                      required
                    />
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 12, marginTop: 8 }}>
                  <button type="submit" className="submit-btn" style={{ flex: 1 }}>
                    <i className="fas fa-shield-alt"></i> UPDATE PASSWORD
                  </button>
                  <button
                    type="button"
                    className="submit-btn"
                    style={{ flex: '0 0 auto', background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-muted)', boxShadow: 'none', padding: '0 20px' }}
                    onClick={() => setActiveTab('streams-section')}
                  >
                    CANCEL
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* ── STREAMS TAB ── */}
          {activeTab === 'streams-section' && (
            <>
          {/* Critical alert banner */}
          {hasUrgentVisible && (
            <div className="critical-alert-bar">
              <div className="critical-alert-icon">
                <i className="fas fa-exclamation-triangle"></i>
              </div>
              <div>
                <div className="critical-alert-title">CRITICAL BROADCAST DETECTED</div>
                <div className="critical-alert-body">
                  Immediate action/review required for urgent transmissions in your stream.
                </div>
              </div>
            </div>
          )}

          {/* Results count */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontWeight: 600 }}>
              <span style={{ color: 'var(--accent)', fontWeight: 800 }}>{filteredStreams.length}</span>
              &nbsp;streams
            </div>
          </div>

          {/* Stream grid */}
          <div className="stream-grid">
            {filteredStreams.length > 0 ? (
              filteredStreams.map((s, idx) => (
                <div
                  key={s._id || idx}
                  className={`notification-card glass-card ${s.is_urgent ? 'urgent-card' : ''}`}
                  style={{ padding: 18, marginBottom: 0 }}
                >
                  {/* Urgent badge */}
                  {s.is_urgent === 1 && (
                    <div className="urgent-banner">
                      <i className="fas fa-bolt"></i> PRIORITY
                    </div>
                  )}

                  {/* Header */}
                  <div className="notification-header">
                    <div className="notification-header-row">
                      <span className="badge badge-accent">
                        {s.category || s.type?.toUpperCase()}
                      </span>
                      <span className="badge badge-neutral">
                        {!s.department ? 'GLOBAL' : 'TARGET'}
                      </span>
                    </div>
                    <h3 className={`notification-title ${s.is_urgent ? 'urgent-title' : ''}`}>
                      {s.title || s.company}
                    </h3>
                    {s.department && (
                      <div style={{ fontSize: 9, color: 'var(--accent)', fontWeight: 700, opacity: 0.85 }}>
                        <i className="fas fa-users" style={{ marginRight: 4 }}></i>
                        {s.department} &nbsp;|&nbsp; Year {s.year}
                      </div>
                    )}
                  </div>

                  {/* Placement details */}
                  {s.type === 'placement' && (
                    <div className="details-mini-grid">
                      <div className="detail-row">
                        <span className="detail-label">Role</span>
                        <span className="detail-value">{s.role}</span>
                      </div>
                      <div className="detail-row">
                        <span className="detail-label">Due</span>
                        <span className="detail-value" style={{ color: 'var(--accent-warn)' }}>{s.deadline}</span>
                      </div>
                    </div>
                  )}

                  {/* Exam details */}
                  {s.type === 'exam' && (
                    <div className="details-mini-grid" style={{ background: 'rgba(255,188,0,0.04)', borderColor: 'rgba(255,188,0,0.12)' }}>
                      <div className="detail-row">
                        <span className="detail-label">Type</span>
                        <span className="detail-value" style={{ color: 'var(--accent-warn)' }}>{s.exam_type}</span>
                      </div>
                    </div>
                  )}

                  {/* Content */}
                  <p className="notification-content">
                    {s.content || s.description}
                  </p>

                  {/* Meta */}
                  <div className="notification-meta">
                    <span>
                      <i className="far fa-clock" style={{ marginRight: 4 }}></i>
                      {formatDate(s.created_at)}
                    </span>
                    {s.posted_by && (
                      <span style={{ color: 'var(--accent)', fontWeight: 700 }}>
                        <i className="fas fa-user-circle" style={{ marginRight: 4 }}></i>
                        {s.posted_by}
                      </span>
                    )}
                  </div>
                </div>
              ))
            ) : (
              <div className="empty-state glass-card">
                <i className="fas fa-satellite-dish"></i>
                <h3>No Active Transmissions</h3>
                <p>No streams match your current filters.</p>
              </div>
            )}
          </div>
          </>
          )}
        </main>
      </div>

      {/* ── Urgent Toast Popups ── */}
      {urgentAlerts.map((alert, idx) => (
        <div key={idx} className="urgent-toast">
          <div className="toast-header">
            <i className="fas fa-bolt"></i> URGENT BROADCAST
          </div>
          <div className="toast-title">{alert.title}</div>
          <div className="toast-body">{alert.content}</div>
          <div className="toast-actions">
            <button className="toast-btn toast-btn-primary" onClick={() => window.location.reload()}>
              REFRESH FEED
            </button>
            <button
              className="toast-btn toast-btn-secondary"
              onClick={() => setUrgentAlerts((prev) => prev.filter((_, i) => i !== idx))}
            >
              DISMISS
            </button>
          </div>
        </div>
      ))}
    </div>
  );
}

export default StudentDashboard;
