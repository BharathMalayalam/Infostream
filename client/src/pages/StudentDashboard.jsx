import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import ThemeToggle from '../components/ThemeToggle';

function StudentDashboard() {
  const [streams, setStreams] = useState([]);
  const [filteredStreams, setFilteredStreams] = useState([]);
  const [search, setSearch] = useState('');
  const [filters, setFilters] = useState({ type: 'all', category: 'all', date: 'all' });
  const [urgentAlerts, setUrgentAlerts] = useState([]);
  
  const navigate = useNavigate();
  const token = localStorage.getItem('token');
  const role = localStorage.getItem('role');

  const fetchStreams = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/student`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setStreams(res.data.streams);
      setFilteredStreams(res.data.streams);
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) navigate('/login');
    }
  };

  useEffect(() => {
    fetchStreams();
    const interval = setInterval(pollUrgentAlerts, 10000);
    if (Notification.permission !== "granted" && Notification.permission !== "denied") {
      Notification.requestPermission();
    }
    return () => clearInterval(interval);
  }, []);

  const [lastUrgentCheck, setLastUrgentCheck] = useState(new Date().toISOString());

  const pollUrgentAlerts = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/urgent_check?since=${encodeURIComponent(lastUrgentCheck)}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (res.data.urgent_alerts && res.data.urgent_alerts.length > 0) {
        setUrgentAlerts(prev => [...prev, ...res.data.urgent_alerts]);
        const maxTime = res.data.urgent_alerts.reduce((max, a) => new Date(a.created_at) > new Date(max) ? a.created_at : max, lastUrgentCheck);
        setLastUrgentCheck(maxTime);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    applyFilters();
  }, [search, filters, streams]);

  const applyFilters = () => {
    const today = new Date().toISOString().split('T')[0];
    const yesterdayDate = new Date();
    yesterdayDate.setDate(yesterdayDate.getDate() - 1);
    const yesterday = yesterdayDate.toISOString().split('T')[0];

    const filtered = streams.filter(s => {
      const type = s.type;
      const cat = s.category;
      const dateStr = s.created_at.split('T')[0];
      const text = (s.title || s.company || s.content || s.description || '').toLowerCase();

      const matchesSearch = text.includes(search.toLowerCase());
      const matchesType = filters.type === 'all' || type === filters.type;
      const matchesCategory = filters.category === 'all' || cat === filters.category;

      let matchesDate = true;
      if (filters.date === 'today') matchesDate = dateStr === today;
      if (filters.date === 'yesterday') matchesDate = dateStr === yesterday;

      return matchesSearch && matchesType && matchesCategory && matchesDate;
    });

    setFilteredStreams(filtered);
  };

  const handleFilterChange = (key, value) => {
    if (key === 'type' && value === 'all') {
      setFilters({ type: 'all', category: 'all', date: 'all' });
    } else {
      setFilters(prev => ({ ...prev, [key]: value }));
    }
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    navigate('/login');
  };

  const hasUrgentVisible = filteredStreams.some(s => s.is_urgent === 1);

  return (
    <div className="container" style={{ maxWidth: '100%', padding: '0 40px' }}>
      <nav className="dashboard-nav" style={{ background: 'var(--card-bg)', backdropFilter: 'var(--glass-blur)', padding: '20px 30px', borderRadius: '20px', border: '1px solid var(--border)', marginTop: '20px' }}>
        <div className="nav-logo" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '32px', height: '32px', background: 'rgba(0, 242, 255, 0.1)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--accent)' }}>
            <i className="fas fa-signal" style={{ color: 'var(--accent)', fontSize: '14px' }}></i>
          </div>
          <span style={{ fontWeight: '800', letterSpacing: '1px' }}>INFOSTREAM</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
          <ThemeToggle />
          <Link to="/" className="logout-link" style={{ background: 'rgba(0, 242, 255, 0.1)', color: 'var(--accent)', padding: '8px 16px', borderRadius: '12px', transition: '0.3s' }}>
            <i className="fas fa-home"></i> HOME
          </Link>
          <button onClick={handleLogout} className="logout-link" style={{ background: 'rgba(255, 68, 68, 0.1)', padding: '8px 16px', borderRadius: '12px', transition: '0.3s', border: 'none', color: '#ff4444', cursor: 'pointer', display: 'flex', gap: '8px', alignItems: 'center' }}>
            <i className="fas fa-power-off"></i> LOGOUT
          </button>
        </div>
      </nav>

      <div style={{ display: 'grid', gridTemplateColumns: '260px 1fr', gap: '30px', marginTop: '30px', alignItems: 'start' }}>
        <aside>
          <div className="glass-card" style={{ padding: '25px', marginBottom: '25px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '25px' }}>
              <div style={{ width: '48px', height: '48px', background: 'var(--accent)', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000' }}>
                <i className="fas fa-user-graduate" style={{ fontSize: '20px' }}></i>
              </div>
              <div>
                <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>Logged In As</div>
                <div style={{ fontWeight: '700', fontSize: '15px' }}>Student</div>
              </div>
            </div>

            <div style={{ borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
              <div className="form-group" style={{ marginBottom: '20px' }}>
                <div style={{ position: 'relative' }}>
                  <i className="fas fa-search" style={{ position: 'absolute', left: '15px', top: '15px', color: 'var(--text-muted)', fontSize: '12px' }}></i>
                  <input type="text" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search posts..." style={{ padding: '12px 15px 12px 42px', fontSize: '13px', margin: '0', background: 'var(--input-bg)', border: '1px solid var(--border)' }} />
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                <button className={`nav-tab ${filters.type === 'all' && filters.category === 'all' && filters.date === 'all' ? 'active' : ''}`} onClick={() => handleFilterChange('type', 'all')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.type === 'all' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', border: '1px solid transparent', color: filters.type === 'all' ? '#fff' : 'var(--text-muted)', padding: '12px 15px' }}>
                  <i className="fas fa-th-large" style={{ width: '20px' }}></i> ALL STREAMS
                </button>

                <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', margin: '15px 0 10px 15px', textTransform: 'uppercase' }}>Category</div>
                <button className={`nav-tab ${filters.category === 'Exam Cell' ? 'active' : ''}`} onClick={() => handleFilterChange('category', 'Exam Cell')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.category === 'Exam Cell' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', color: filters.category === 'Exam Cell' ? '#fff' : 'var(--text-muted)', padding: '10px 15px', border: '1px solid transparent' }}>
                  <i className="fas fa-file-invoice" style={{ width: '20px' }}></i> EXAM CELL
                </button>
                <button className={`nav-tab ${filters.category === 'Placement' ? 'active' : ''}`} onClick={() => handleFilterChange('category', 'Placement')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.category === 'Placement' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', color: filters.category === 'Placement' ? '#fff' : 'var(--text-muted)', padding: '10px 15px', border: '1px solid transparent' }}>
                  <i className="fas fa-briefcase" style={{ width: '20px' }}></i> PLACEMENTS
                </button>
                <button className={`nav-tab ${filters.category === 'Events' ? 'active' : ''}`} onClick={() => handleFilterChange('category', 'Events')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.category === 'Events' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', color: filters.category === 'Events' ? '#fff' : 'var(--text-muted)', padding: '10px 15px', border: '1px solid transparent' }}>
                  <i className="fas fa-calendar-alt" style={{ width: '20px' }}></i> EVENTS
                </button>

                <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', margin: '15px 0 10px 15px', textTransform: 'uppercase' }}>Timeline</div>
                <button className={`nav-tab ${filters.date === 'today' ? 'active' : ''}`} onClick={() => handleFilterChange('date', 'today')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.date === 'today' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', color: filters.date === 'today' ? '#fff' : 'var(--text-muted)', padding: '10px 15px', border: '1px solid transparent' }}>
                  <i className="fas fa-clock" style={{ width: '20px' }}></i> TODAY
                </button>
                <button className={`nav-tab ${filters.date === 'yesterday' ? 'active' : ''}`} onClick={() => handleFilterChange('date', 'yesterday')} style={{ width: '100%', justifyContent: 'flex-start', background: filters.date === 'yesterday' ? 'rgba(255, 255, 255, 0.05)' : 'transparent', color: filters.date === 'yesterday' ? '#fff' : 'var(--text-muted)', padding: '10px 15px', border: '1px solid transparent' }}>
                  <i className="fas fa-history" style={{ width: '20px' }}></i> YESTERDAY
                </button>
              </div>
            </div>
          </div>

          <div className="glass-card" style={{ padding: '20px', background: 'rgba(0, 242, 255, 0.03)' }}>
            <div style={{ fontSize: '11px', fontWeight: '800', color: 'var(--accent)', marginBottom: '15px', textTransform: 'uppercase', letterSpacing: '1px' }}>System Status</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', fontSize: '12px', color: 'var(--text-muted)' }}>
              <div style={{ width: '8px', height: '8px', background: '#adff00', borderRadius: '50%', boxShadow: '0 0 8px #adff00' }}></div>
              Operational & Encrypted
            </div>
          </div>
        </aside>

        <main style={{ paddingBottom: '60px' }}>
          {hasUrgentVisible && (
            <div style={{ background: 'rgba(255, 77, 77, 0.1)', border: '1px solid rgba(255, 77, 77, 0.2)', padding: '20px', borderRadius: '16px', marginBottom: '25px', display: 'flex', alignItems: 'center', gap: '15px', animation: 'pulse 2s infinite' }}>
              <div style={{ width: '40px', height: '40px', background: '#ff4d4d', borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', boxShadow: '0 0 15px rgba(255, 77, 77, 0.4)' }}>
                <i className="fas fa-exclamation-triangle"></i>
              </div>
              <div>
                <div style={{ color: '#ff4d4d', fontWeight: '800', fontSize: '12px', letterSpacing: '1px' }}>CRITICAL BROADCAST DETECTED</div>
                <div style={{ color: 'var(--text-muted)', fontSize: '13px' }}>Immediate action/review required for urgent transmissions in your stream.</div>
              </div>
            </div>
          )}

          {urgentAlerts.map((alert, idx) => (
            <div key={idx} className="glass-card" style={{ position: 'fixed', bottom: '30px', right: '30px', width: '350px', padding: '25px', background: 'rgba(20, 20, 20, 0.95)', border: '2px solid #ff4d4d', boxShadow: '0 10px 40px rgba(255, 77, 77, 0.3)', zIndex: 9999 }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: '15px' }}>
                <div style={{ width: '40px', height: '40px', background: '#ff4d4d', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'white', flexShrink: 0, boxShadow: '0 0 15px rgba(255, 77, 77, 0.4)' }}>
                  <i className="fas fa-bolt"></i>
                </div>
                <div style={{ flexGrow: 1 }}>
                  <div style={{ color: '#ff4d4d', fontWeight: '800', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '2px', marginBottom: '5px' }}>URGENT BROADCAST</div>
                  <div style={{ color: '#fff', fontWeight: '700', fontSize: '15px', marginBottom: '5px' }}>{alert.title}</div>
                  <div style={{ color: 'var(--text-muted)', fontSize: '12px', lineHeight: '1.4' }}>{alert.content}</div>
                  <div style={{ marginTop: '15px', display: 'flex', gap: '10px' }}>
                    <button onClick={() => window.location.reload()} style={{ background: 'var(--accent)', color: '#000', border: 'none', padding: '6px 12px', borderRadius: '6px', fontSize: '10px', fontWeight: '800', cursor: 'pointer' }}>REFRESH FEED</button>
                    <button onClick={() => setUrgentAlerts(prev => prev.filter((_, i) => i !== idx))} style={{ background: 'transparent', color: 'var(--text-muted)', border: '1px solid var(--border)', padding: '6px 12px', borderRadius: '6px', fontSize: '10px', fontWeight: '800', cursor: 'pointer' }}>DISMISS</button>
                  </div>
                </div>
              </div>
            </div>
          ))}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '15px' }}>
            {filteredStreams.length > 0 ? filteredStreams.map((s, idx) => (
              <div key={idx} className={`notification-card glass-card ${s.is_urgent ? 'urgent-card' : ''}`} style={{ padding: '18px', marginBottom: '0', position: 'relative', display: 'flex', flexDirection: 'column', minHeight: '280px', border: '1px solid var(--border)' }}>
                {s.is_urgent === 1 && (
                  <div className="urgent-bg" style={{ position: 'absolute', top: 0, right: 0, color: '#fff', fontSize: '8px', fontWeight: '900', padding: '4px 12px', borderBottomLeftRadius: '12px', letterSpacing: '1px' }}>
                    <i className="fas fa-bolt"></i> PRIORITY TRANSMISSION
                  </div>
                )}
                <div className="notification-header" style={{ marginBottom: '12px', display: 'block' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                    <span className="category-badge" style={{ background: 'rgba(0, 242, 255, 0.1)', color: 'var(--accent)', fontSize: '8px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px', padding: '2px 8px', borderRadius: '4px', border: '1px solid rgba(0, 242, 255, 0.2)' }}>
                      {s.category || s.type.toUpperCase()}
                    </span>
                    <span className="badge" style={{ background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)', border: '1px solid var(--border)', fontSize: '8px', padding: '2px 6px' }}>
                      {!s.department ? 'GLOBAL' : 'TARGET'}
                    </span>
                  </div>
                  <h3 className={`notification-title ${s.is_urgent ? 'urgent-title' : ''}`} style={{ marginTop: '4px', fontSize: '14px', fontWeight: '800', color: 'var(--text-primary)', lineHeight: '1.3', overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' }}>
                    {s.title || s.company}
                  </h3>
                  {s.department && (
                    <div style={{ fontSize: '8px', color: 'var(--accent)', fontWeight: '700', opacity: '0.8', marginTop: '4px' }}>
                      <i className="fas fa-users" style={{ marginRight: '3px' }}></i> {s.department} | {s.year}
                    </div>
                  )}
                </div>

                {s.type === 'placement' && (
                  <div className="details-mini-grid" style={{ display: 'flex', flexDirection: 'column', gap: '6px', margin: '10px 0', background: 'rgba(255,255,255,0.03)', padding: '8px', borderRadius: '8px', border: '1px solid var(--border)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '8px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Role</span>
                      <span style={{ fontSize: '10px', fontWeight: '700', color: 'var(--text-primary)' }}>{s.role}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '8px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Due</span>
                      <span style={{ fontSize: '10px', fontWeight: '700', color: '#ffbc00' }}>{s.deadline}</span>
                    </div>
                  </div>
                )}
                {s.type === 'exam' && (
                  <div className="details-mini-grid" style={{ margin: '10px 0', background: 'rgba(255,188,0,0.05)', padding: '8px', borderRadius: '8px', border: '1px solid rgba(255,188,0,0.1)' }}>
                    <div style={{ fontSize: '8px', fontWeight: '800', color: '#ffbc00', textTransform: 'uppercase', marginBottom: '2px' }}>Type</div>
                    <div style={{ fontSize: '10px', fontWeight: '700', color: 'var(--text-primary)' }}>{s.exam_type}</div>
                  </div>
                )}

                <div className="notification-content" style={{ margin: '8px 0', fontSize: '11px', color: 'var(--text-muted)', lineHeight: '1.5', whiteSpace: 'pre-wrap', overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 4, WebkitBoxOrient: 'vertical', flexGrow: 1 }}>
                  {s.content || s.description}
                </div>

                <div className="notification-meta" style={{ paddingTop: '10px', borderTop: '1px solid var(--border)', marginTop: 'auto' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: '9px' }}><i className="far fa-clock"></i> {s.created_at.split('T')[0]}</span>
                    {s.posted_by && <span style={{ color: 'var(--accent)', fontWeight: '700', fontSize: '9px' }}><i className="fas fa-user-circle"></i> {s.posted_by}</span>}
                  </div>
                </div>
              </div>
            )) : (
              <div className="glass-card" style={{ textAlign: 'center', padding: '100px 40px', gridColumn: '1 / -1' }}>
                <i className="fas fa-satellite-dish" style={{ fontSize: '32px', color: 'var(--text-muted)', marginBottom: '20px' }}></i>
                <h3 style={{ fontSize: '18px', fontWeight: '700' }}>End of Stream</h3>
                <p style={{ color: 'var(--text-muted)' }}>No active transmissions detected.</p>
              </div>
            )}
          </div>
        </main>
      </div>
    </div>
  );
}

export default StudentDashboard;
