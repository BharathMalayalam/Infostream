import React, { useState, useEffect, useCallback } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from '../api/axios';
import ThemeToggle from '../components/ThemeToggle';
import useAuth from '../context/useAuth';

/* ─── Cookie helpers ─── */
function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

function setCookie(name, value, days = 365) {
  const date = new Date();
  date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value};path=/;expires=${date.toUTCString()};SameSite=Lax`;
}

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

function AdminDashboard() {
  const [activeTab, setActiveTab] = useState(
    () => getCookie('activeAdminTab') || 'broadcast-section'
  );
  const [data, setData] = useState({ notifications: [], placements: [], exams: [], users: [] });
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [toast, setToast] = useState(null); // { message, type }
  const [userSearch, setUserSearch] = useState('');

  const { logout, user } = useAuth();
  const role = user?.role;

  // Form states
  const [broadcast, setBroadcast] = useState({
    title: '', category: 'Events', content: '', type: 'all', department: [], year: [], is_urgent: false,
  });
  const [placement, setPlacement] = useState({
    company: '', role: '', eligibility: '', deadline: '', description: '', is_urgent: false,
  });
  const [exam, setExam] = useState({
    exam_type: 'Internal Test', title: '', content: '', department: [], year: [], is_urgent: false,
  });

  // Users forms
  const [adminForm, setAdminForm] = useState({ username: '', password: '', phone: '' });
  const [staffForm, setStaffForm] = useState({ username: '', password: '', phone: '' });
  const [studentForm, setStudentForm] = useState({ username: '', password: '', phone: '', department: 'CSE', year: '1' });

  const navigate = useNavigate();

  const showToast = (message, type = 'success') => setToast({ message, type });
  const dismissToast = () => setToast(null);

  /* ─── Fetch ─── */
  const fetchDashboard = useCallback(async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/admin`);
      setData(res.data);
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) navigate('/login');
    }
  }, [navigate]);

  useEffect(() => { fetchDashboard(); }, [fetchDashboard]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    setCookie('activeAdminTab', tab);
    setSidebarOpen(false);
  };

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  };

  /* ─── Checkbox helper ─── */
  const handleCheckbox = (stateObj, setFn, field, value) => {
    const list = stateObj[field];
    setFn({
      ...stateObj,
      [field]: list.includes(value) ? list.filter((v) => v !== value) : [...list, value],
    });
  };

  /* ─── Submit handlers ─── */
  const handleBroadcastSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/notifications`, broadcast);
      showToast('Notification published successfully!');
      setBroadcast({ title: '', category: 'Events', content: '', type: 'all', department: [], year: [], is_urgent: false });
      fetchDashboard();
    } catch (err) {
      console.warn('Broadcast submit failed:', err?.message || err);
      showToast(err.response?.data?.message || 'Failed to publish notification.', 'error');
    }
  };

  const handlePlacementSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/placements`, placement);
      showToast('Placement posted successfully!');
      setPlacement({ company: '', role: '', eligibility: '', deadline: '', description: '', is_urgent: false });
      fetchDashboard();
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to post placement.', 'error');
    }
  };

  const handleExamSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/exams`, exam);
      showToast('Exam notice published!');
      setExam({ exam_type: 'Internal Test', title: '', content: '', department: [], year: [], is_urgent: false });
      fetchDashboard();
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to post exam notice.', 'error');
    }
  };

  const handleDelete = async (userId) => {
    if (!window.confirm('Revoke this user identity?')) return;
    try {
      await axios.delete(`${import.meta.env.VITE_API_URL}/api/auth/users/${userId}`);
      showToast('User revoked successfully.');
      fetchDashboard();
    } catch {
      showToast('Failed to revoke user.', 'error');
    }
  };

  const handleAdminSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/users/admin`, adminForm);
      showToast(`Super Admin account created for ${adminForm.username}`);
      setAdminForm({ username: '', password: '', phone: '' });
      fetchDashboard();
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to create admin account.', 'error');
    }
  };

  const [passwordForm, setPasswordForm] = useState({ currentPassword: '', newPassword: '' });

  const handlePasswordChange = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/change-password`, passwordForm);
      showToast('Password changed successfully!');
      setPasswordForm({ currentPassword: '', newPassword: '' });
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to change password.', 'error');
    }
  };

  const handleStaffSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/users/staff`, staffForm);
      showToast(`Staff account created for ${staffForm.username}`);
      setStaffForm({ username: '', password: '', phone: '' });
      fetchDashboard();
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to create staff account.', 'error');
    }
  };

  const handleStudentSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/users/student`, studentForm);
      showToast(`Student account created for ${studentForm.username}`);
      setStudentForm({ username: '', password: '', phone: '', department: 'CSE', year: '1' });
      fetchDashboard();
    } catch (err) {
      showToast(err.response?.data?.message || 'Failed to create student account.', 'error');
    }
  };

  const depts = ['CSE', 'ECE', 'IT', 'MECH', 'CIVIL', 'AUTO'];
  const years = ['1', '2', '3', '4'];

  const navTabs = [
    { id: 'broadcast-section', icon: 'fa-broadcast-tower', label: 'BROADCAST' },
    { id: 'placement-section', icon: 'fa-briefcase',        label: 'PLACEMENTS' },
    { id: 'exam-section',      icon: 'fa-file-invoice',     label: 'EXAMS' },
    ...(role === 'admin' ? [{ id: 'roster-section', icon: 'fa-users-cog', label: 'ROSTER' }] : []),
    { id: 'settings-section',  icon: 'fa-cog',              label: 'SETTINGS' },
  ];

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
            <span></span><span></span><span></span>
          </button>
          <div className="nav-brand-icon">
            <i className="fas fa-signal"></i>
          </div>
          <span className="nav-brand-text">
            INFOSTREAM
            {role && <span className="nav-role-badge">{role.toUpperCase()}</span>}
          </span>
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

      <div className="dashboard-layout">
        {/* Mobile overlay */}
        <div
          className={`sidebar-overlay ${sidebarOpen ? '' : 'hidden'}`}
          onClick={() => setSidebarOpen(false)}
        />

        {/* ── Sidebar ── */}
        <aside className={`sidebar ${sidebarOpen ? 'open' : ''}`}>
          <div className="sidebar-profile">
            <div className="profile-avatar" style={{ background: 'rgba(0,242,255,0.1)', color: 'var(--accent)', border: '1px solid rgba(0,242,255,0.2)' }}>
              <i className="fas fa-terminal"></i>
            </div>
            <div>
              <div className="profile-info-label">Command Console</div>
              <div className="profile-info-value" style={{ textTransform: 'capitalize' }}>{user?.username}</div>
              <div style={{ fontSize: 10, color: 'var(--accent)', fontWeight: 700, letterSpacing: '0.5px' }}>{role === 'admin' ? 'SUPER ADMIN' : 'STAFF'}</div>
            </div>
          </div>

          <nav>
            {navTabs.map(({ id, icon, label }) => (
              <button
                key={id}
                className={`nav-tab ${activeTab === id ? 'active-filled' : ''}`}
                onClick={() => handleTabChange(id)}
              >
                <i className={`fas ${icon}`}></i>
                {label}
              </button>
            ))}
          </nav>

          <div className="system-status">
            <div className="status-dot"></div>
            <span className="status-text">Admin Console Active</span>
          </div>
        </aside>

        {/* ── Main Content ── */}
        <main className="dashboard-main">
          {/* Toast */}
          {toast && <Toast message={toast.message} type={toast.type} onDismiss={dismissToast} />}

          {/* ── BROADCAST ── */}
          {activeTab === 'broadcast-section' && (
            <div className="glass-card" style={{ padding: '32px' }}>
              <div className="section-header">
                <div className="section-icon" style={{ background: 'var(--accent)' }}>
                  <i className="fas fa-broadcast-tower"></i>
                </div>
                <h2 className="section-title">INITIATE BROADCAST</h2>
              </div>

              <form onSubmit={handleBroadcastSubmit}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="form-grid-2">
                  <div className="form-group">
                    <label className="form-label">Title</label>
                    <input
                      value={broadcast.title}
                      onChange={(e) => setBroadcast({ ...broadcast, title: e.target.value })}
                      placeholder="Enter broadcast title..."
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Category</label>
                    <select
                      value={broadcast.category}
                      onChange={(e) => setBroadcast({ ...broadcast, category: e.target.value })}
                      style={{ color: 'var(--accent)', fontWeight: 700 }}
                    >
                      <option value="Events">Events</option>
                      <option value="department">Specific Department/Year</option>
                      <option value="Exam Cell">Exam Cell</option>
                    </select>
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Message</label>
                  <textarea
                    value={broadcast.content}
                    onChange={(e) => setBroadcast({ ...broadcast, content: e.target.value })}
                    rows={4}
                    placeholder="Input detailed transmission data..."
                    required
                  />
                </div>

                <div style={{ display: 'flex', alignItems: 'flex-end', gap: 16, flexWrap: 'wrap', marginBottom: 22 }}>
                  <div className="form-group" style={{ marginBottom: 0, flex: '1 1 180px' }}>
                    <label className="form-label">Send To</label>
                    <select
                      value={broadcast.type}
                      onChange={(e) => setBroadcast({ ...broadcast, type: e.target.value })}
                      style={{ color: 'var(--accent)', fontWeight: 700 }}
                    >
                      <option value="all">Everyone</option>
                      <option value="department">Sector Restricted (Dept/Phase)</option>
                    </select>
                  </div>
                  <label className="urgent-checkbox-label red">
                    <input
                      type="checkbox"
                      checked={broadcast.is_urgent}
                      onChange={(e) => setBroadcast({ ...broadcast, is_urgent: e.target.checked })}
                    />
                    <i className="fas fa-exclamation-triangle"></i> MARK AS URGENT
                  </label>
                </div>

                {broadcast.type === 'department' && (
                  <div className="target-fields" style={{ marginBottom: 22 }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24 }} className="form-grid-2">
                      <div className="form-group" style={{ marginBottom: 0 }}>
                        <label className="form-label">Target Sector(s)</label>
                        <div className="checkbox-group">
                          {depts.map((d) => (
                            <label key={d} className="checkbox-item">
                              <input
                                type="checkbox"
                                checked={broadcast.department.includes(d)}
                                onChange={() => handleCheckbox(broadcast, setBroadcast, 'department', d)}
                              />
                              {d}
                            </label>
                          ))}
                        </div>
                      </div>
                      <div className="form-group" style={{ marginBottom: 0 }}>
                        <label className="form-label">Sector Phase(s)</label>
                        <div className="checkbox-group">
                          {years.map((y) => (
                            <label key={y} className="checkbox-item">
                              <input
                                type="checkbox"
                                checked={broadcast.year.includes(y)}
                                onChange={() => handleCheckbox(broadcast, setBroadcast, 'year', y)}
                              />
                              Phase {y}
                            </label>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                <button type="submit" className="submit-btn">
                  <i className="fas fa-satellite-dish"></i> PUBLISH BROADCAST
                </button>
              </form>
            </div>
          )}

          {/* ── PLACEMENTS ── */}
          {activeTab === 'placement-section' && (
            <div className="glass-card" style={{ padding: '32px' }}>
              <div className="section-header">
                <div className="section-icon" style={{ background: '#adff00' }}>
                  <i className="fas fa-briefcase"></i>
                </div>
                <h2 className="section-title">PLACEMENT DISPATCH</h2>
              </div>

              <form onSubmit={handlePlacementSubmit}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="form-grid-2">
                  <div className="form-group">
                    <label className="form-label">Company Name</label>
                    <input
                      value={placement.company}
                      onChange={(e) => setPlacement({ ...placement, company: e.target.value })}
                      placeholder="e.g. Nexus Dynamics"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Job Title</label>
                    <input
                      value={placement.role}
                      onChange={(e) => setPlacement({ ...placement, role: e.target.value })}
                      placeholder="e.g. Systems Architect"
                      required
                    />
                  </div>
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="form-grid-2">
                  <div className="form-group">
                    <label className="form-label">Eligibility Criteria</label>
                    <input
                      value={placement.eligibility}
                      onChange={(e) => setPlacement({ ...placement, eligibility: e.target.value })}
                      placeholder="e.g. CGPA &gt; 8.0"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label className="form-label">Apply By Date</label>
                    <input
                      type="date"
                      value={placement.deadline}
                      onChange={(e) => setPlacement({ ...placement, deadline: e.target.value })}
                      required
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Job Description</label>
                  <textarea
                    value={placement.description}
                    onChange={(e) => setPlacement({ ...placement, description: e.target.value })}
                    rows={4}
                    placeholder="Enter job details..."
                    required
                  />
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 24 }}>
                  <label className="urgent-checkbox-label green">
                    <input
                      type="checkbox"
                      checked={placement.is_urgent}
                      onChange={(e) => setPlacement({ ...placement, is_urgent: e.target.checked })}
                    />
                    <i className="fas fa-bolt"></i> MARK AS URGENT
                  </label>
                </div>

                <button
                  type="submit"
                  className="submit-btn"
                  style={{ background: '#adff00', boxShadow: '0 4px 20px rgba(173,255,0,0.25)' }}
                >
                  <i className="fas fa-upload"></i> POST JOB
                </button>
              </form>
            </div>
          )}

          {/* ── EXAMS ── */}
          {activeTab === 'exam-section' && (
            <div className="glass-card" style={{ padding: '32px' }}>
              <div className="section-header">
                <div className="section-icon" style={{ background: 'var(--accent-warn)' }}>
                  <i className="fas fa-file-invoice"></i>
                </div>
                <h2 className="section-title">POST EXAM NOTICE</h2>
              </div>

              <form onSubmit={handleExamSubmit}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="form-grid-2">
                  <div className="form-group">
                    <label className="form-label">Exam Type</label>
                    <select
                      value={exam.exam_type}
                      onChange={(e) => setExam({ ...exam, exam_type: e.target.value })}
                      style={{ color: 'var(--accent-warn)', fontWeight: 700 }}
                    >
                      <option value="Internal Test">Internal Test</option>
                      <option value="University Exam">University Exam</option>
                      <option value="Results">Results</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>
                  <div className="form-group">
                    <label className="form-label">Title</label>
                    <input
                      value={exam.title}
                      onChange={(e) => setExam({ ...exam, title: e.target.value })}
                      placeholder="e.g. Semester 5 Main Examination"
                      required
                    />
                  </div>
                </div>

                <div className="form-group">
                  <label className="form-label">Details</label>
                  <textarea
                    value={exam.content}
                    onChange={(e) => setExam({ ...exam, content: e.target.value })}
                    rows={4}
                    placeholder="Enter exam details..."
                    required
                  />
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 24, marginBottom: 22 }} className="form-grid-2">
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Select Department(s)</label>
                    <div className="checkbox-group">
                      {depts.map((d) => (
                        <label key={d} className="checkbox-item">
                          <input
                            type="checkbox"
                            checked={exam.department.includes(d)}
                            onChange={() => handleCheckbox(exam, setExam, 'department', d)}
                          />
                          {d}
                        </label>
                      ))}
                    </div>
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Select Year(s)</label>
                    <div className="checkbox-group">
                      {years.map((y) => (
                        <label key={y} className="checkbox-item">
                          <input
                            type="checkbox"
                            checked={exam.year.includes(y)}
                            onChange={() => handleCheckbox(exam, setExam, 'year', y)}
                          />
                          Phase {y}
                        </label>
                      ))}
                    </div>
                  </div>
                </div>

                <label className="urgent-checkbox-label yellow" style={{ marginBottom: 24 }}>
                  <input
                    type="checkbox"
                    checked={exam.is_urgent}
                    onChange={(e) => setExam({ ...exam, is_urgent: e.target.checked })}
                  />
                  <i className="fas fa-exclamation-circle"></i> MARK AS URGENT
                </label>

                <button
                  type="submit"
                  className="submit-btn"
                  style={{ background: 'transparent', border: '1px solid var(--accent-warn)', color: 'var(--accent-warn)', boxShadow: 'none' }}
                >
                  <i className="fas fa-check-double"></i> POST EXAM NOTICE
                </button>
              </form>
            </div>
          )}

          {/* ── SETTINGS ── */}
          {activeTab === 'settings-section' && (
            <div className="glass-card" style={{ padding: '32px', maxWidth: '480px', margin: '0 auto' }}>
              <div className="section-header">
                <div className="section-icon" style={{ background: 'var(--accent)' }}>
                  <i className="fas fa-key" style={{ color: '#000' }}></i>
                </div>
                <h2 className="section-title">CHANGE PASSWORD</h2>
              </div>
              <form onSubmit={handlePasswordChange}>
                <div className="form-group">
                  <label className="form-label">Current Password</label>
                  <input
                    type="password"
                    value={passwordForm.currentPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, currentPassword: e.target.value })}
                    placeholder="Enter current password"
                    required
                  />
                </div>
                <div className="form-group">
                  <label className="form-label">New Password</label>
                  <input
                    type="password"
                    value={passwordForm.newPassword}
                    onChange={(e) => setPasswordForm({ ...passwordForm, newPassword: e.target.value })}
                    placeholder="Enter new password"
                    required
                  />
                </div>
                <button type="submit" className="submit-btn" style={{ marginTop: 10 }}>
                  UPDATE PASSWORD
                </button>
              </form>
            </div>
          )}

          {/* ── ROSTER ── */}
          {activeTab === 'roster-section' && role === 'admin' && (
            <div>
              {/* Stat cards */}
              <div className="stat-grid">
                <div className="stat-card" style={{ borderLeft: '3px solid var(--accent)' }}>
                  <div className="stat-label">Total Users</div>
                  <div className="stat-value">
                    {data.users.length}
                    <span className="stat-unit">Users</span>
                  </div>
                </div>
                <div className="stat-card" style={{ borderLeft: '3px solid #adff00' }}>
                  <div className="stat-label">Staff Members</div>
                  <div className="stat-value">
                    {data.users.filter((u) => u.role === 'staff').length}
                    <span className="stat-unit">Staff</span>
                  </div>
                </div>
                <div className="stat-card" style={{ borderLeft: '3px solid var(--accent-warn)' }}>
                  <div className="stat-label">Registered Students</div>
                  <div className="stat-value">
                    {data.users.filter((u) => u.role === 'student').length}
                    <span className="stat-unit">Students</span>
                  </div>
                </div>
              </div>

              {/* Account Provisioning Forms */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 20, marginBottom: 30 }} className="form-grid-3">
                {/* Provision Super Admin */}
                <div className="glass-card" style={{ padding: 24 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                    <div style={{ width: 32, height: 32, background: 'rgba(0, 242, 255, 0.1)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', border: '1px solid rgba(0, 242, 255, 0.2)' }}>
                      <i className="fas fa-user-shield"></i>
                    </div>
                    <h3 style={{ fontSize: 14, fontWeight: 800, letterSpacing: '0.5px', textTransform: 'uppercase' }}>PROVISION ADMIN</h3>
                  </div>
                  <form onSubmit={handleAdminSubmit}>
                    <div className="form-group">
                      <label className="form-label">Username</label>
                      <input
                        value={adminForm.username}
                        onChange={(e) => setAdminForm({ ...adminForm, username: e.target.value })}
                        placeholder="Admin username"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Password</label>
                      <input
                        type="password"
                        value={adminForm.password}
                        onChange={(e) => setAdminForm({ ...adminForm, password: e.target.value })}
                        placeholder="Password"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Phone Number</label>
                      <input
                        value={adminForm.phone}
                        onChange={(e) => setAdminForm({ ...adminForm, phone: e.target.value })}
                        placeholder="Phone number"
                      />
                    </div>
                    <button type="submit" className="submit-btn" style={{ background: 'var(--accent)', color: '#000', boxShadow: '0 4px 15px rgba(0, 242, 255, 0.2)', padding: '10px 16px', fontSize: 11 }}>
                      CREATE ADMIN NODE
                    </button>
                  </form>
                </div>

                {/* Provision Staff */}
                <div className="glass-card" style={{ padding: 24 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                    <div style={{ width: 32, height: 32, background: 'rgba(173, 255, 0, 0.1)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#adff00', border: '1px solid rgba(173, 255, 0, 0.2)' }}>
                      <i className="fas fa-user-tie"></i>
                    </div>
                    <h3 style={{ fontSize: 14, fontWeight: 800, letterSpacing: '0.5px', textTransform: 'uppercase' }}>PROVISION STAFF</h3>
                  </div>
                  <form onSubmit={handleStaffSubmit}>
                    <div className="form-group">
                      <label className="form-label">Username</label>
                      <input
                        value={staffForm.username}
                        onChange={(e) => setStaffForm({ ...staffForm, username: e.target.value })}
                        placeholder="Staff username"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Password</label>
                      <input
                        type="password"
                        value={staffForm.password}
                        onChange={(e) => setStaffForm({ ...staffForm, password: e.target.value })}
                        placeholder="Password"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Phone Number</label>
                      <input
                        value={staffForm.phone}
                        onChange={(e) => setStaffForm({ ...staffForm, phone: e.target.value })}
                        placeholder="Phone number"
                      />
                    </div>
                    <button type="submit" className="submit-btn" style={{ background: '#adff00', color: '#000', boxShadow: '0 4px 15px rgba(173, 255, 0, 0.2)', padding: '10px 16px', fontSize: 11 }}>
                      CREATE STAFF NODE
                    </button>
                  </form>
                </div>

                {/* Provision Student */}
                <div className="glass-card" style={{ padding: 24 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                    <div style={{ width: 32, height: 32, background: 'rgba(255, 188, 0, 0.1)', borderRadius: 8, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffbc00', border: '1px solid rgba(255, 188, 0, 0.2)' }}>
                      <i className="fas fa-user-graduate"></i>
                    </div>
                    <h3 style={{ fontSize: 14, fontWeight: 800, letterSpacing: '0.5px', textTransform: 'uppercase' }}>PROVISION STUDENT</h3>
                  </div>
                  <form onSubmit={handleStudentSubmit}>
                    <div className="form-group">
                      <label className="form-label">Username</label>
                      <input
                        value={studentForm.username}
                        onChange={(e) => setStudentForm({ ...studentForm, username: e.target.value })}
                        placeholder="Student username"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Password</label>
                      <input
                        type="password"
                        value={studentForm.password}
                        onChange={(e) => setStudentForm({ ...studentForm, password: e.target.value })}
                        placeholder="Password"
                        required
                      />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Phone Number</label>
                      <input
                        value={studentForm.phone}
                        onChange={(e) => setStudentForm({ ...studentForm, phone: e.target.value })}
                        placeholder="Phone number"
                      />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }} className="form-grid-2">
                      <div className="form-group">
                        <label className="form-label">Department</label>
                        <select value={studentForm.department} onChange={(e) => setStudentForm({ ...studentForm, department: e.target.value })}>
                          {depts.map(d => <option key={d} value={d}>{d}</option>)}
                        </select>
                      </div>
                      <div className="form-group">
                        <label className="form-label">Year</label>
                        <select value={studentForm.year} onChange={(e) => setStudentForm({ ...studentForm, year: e.target.value })}>
                          {years.map(y => <option key={y} value={y}>{y}</option>)}
                        </select>
                      </div>
                    </div>
                    <button type="submit" className="submit-btn" style={{ background: 'var(--accent-warn)', color: '#000', boxShadow: '0 4px 15px rgba(255, 188, 0, 0.2)', padding: '10px 16px', fontSize: 11 }}>
                      PROVISION STUDENT
                    </button>
                  </form>
                </div>
              </div>

              {/* User list */}
              <div className="glass-card" style={{ padding: '28px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24, flexWrap: 'wrap', gap: 16 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{ width: 40, height: 40, background: 'rgba(0,242,255,0.08)', borderRadius: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', border: '1px solid rgba(0,242,255,0.15)' }}>
                      <i className="fas fa-fingerprint"></i>
                    </div>
                    <h3 style={{ fontSize: 18, fontWeight: 800, letterSpacing: '1px' }}>USER ROSTER</h3>
                  </div>
                  <div className="search-wrapper" style={{ width: 'min(280px, 100%)' }}>
                    <i className="fas fa-search"></i>
                    <input
                      type="text"
                      value={userSearch}
                      onChange={(e) => setUserSearch(e.target.value)}
                      placeholder="Search users..."
                    />
                  </div>
                </div>

                <div className="user-table-wrapper">
                  <table className="user-table">
                    <thead>
                      <tr>
                        <th>Username</th>
                        <th>Role</th>
                        <th className="col-dept">Department</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.users
                        .filter((u) => u.username.toLowerCase().includes(userSearch.toLowerCase()))
                        .map((u) => (
                          <tr key={u._id}>
                            <td>
                              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                                <div className="user-avatar">
                                  <i className="fas fa-id-badge"></i>
                                </div>
                                <div>
                                  <div className="user-name">{u.username}</div>
                                  <div className="user-id">
                                    ID: {u._id.substring(0, 8)}
                                    {u.phone && (
                                      <span style={{ marginLeft: 8, color: 'var(--accent)', opacity: 0.8 }}>
                                        <i className="fas fa-phone-alt" style={{ fontSize: 8, marginRight: 3 }}></i>
                                        {u.phone}
                                      </span>
                                    )}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td>
                              {u.role === 'admin' ? (
                                <span className="badge badge-accent">SUPER USER</span>
                              ) : u.role === 'staff' ? (
                                <span className="badge badge-secondary">STAFF</span>
                              ) : (
                                <span className="badge badge-warn">STUDENT</span>
                              )}
                            </td>
                            <td className="col-dept">
                              {u.department ? (
                                <div>
                                  <div style={{ fontWeight: 700, fontSize: 12, color: 'var(--text-primary)' }}>{u.department}</div>
                                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Phase {u.year}</div>
                                </div>
                              ) : (
                                <span style={{ fontSize: 11, color: '#444', fontWeight: 800, letterSpacing: '1px' }}>CORE ACCESS</span>
                              )}
                            </td>
                            <td>
                              {u._id !== user?.id ? (
                                <button className="revoke-btn" onClick={() => handleDelete(u._id)}>
                                  <i className="fas fa-shield-virus"></i> REVOKE
                                </button>
                              ) : (
                                <div className="immutable-tag">
                                  <i className="fas fa-lock"></i> IMMUTABLE (Self)
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default AdminDashboard;
