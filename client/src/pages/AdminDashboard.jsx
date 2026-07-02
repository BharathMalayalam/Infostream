import React, { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import ThemeToggle from '../components/ThemeToggle';

function AdminDashboard() {
  const [activeTab, setActiveTab] = useState(localStorage.getItem('activeAdminTab') || 'broadcast-section');
  const [data, setData] = useState({ notifications: [], placements: [], exams: [], users: [] });
  const [role, setRole] = useState(localStorage.getItem('role'));
  const navigate = useNavigate();

  // Forms states
  const [broadcast, setBroadcast] = useState({ title: '', category: 'Events', content: '', type: 'all', department: [], year: [], is_urgent: false });
  const [placement, setPlacement] = useState({ company: '', role: '', eligibility: '', deadline: '', description: '', is_urgent: false });
  const [exam, setExam] = useState({ exam_type: 'Internal Test', title: '', content: '', department: [], year: [], is_urgent: false });

  // Users forms
  const [staffForm, setStaffForm] = useState({ username: '', password: '', phone: '' });
  const [studentForm, setStudentForm] = useState({ username: '', password: '', phone: '', department: 'CSE', year: '1' });
  const [userSearch, setUserSearch] = useState('');

  const fetchDashboard = async () => {
    try {
      const res = await axios.get(`${import.meta.env.VITE_API_URL}/api/auth/admin`, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      setData(res.data);
    } catch (err) {
      if (err.response?.status === 401 || err.response?.status === 403) {
        navigate('/login');
      }
    }
  };

  useEffect(() => {
    fetchDashboard();
  }, [navigate]);

  const handleTabChange = (tab) => {
    setActiveTab(tab);
    localStorage.setItem('activeAdminTab', tab);
  };

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('role');
    navigate('/login');
  };

  const handleBroadcastSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/notifications`, broadcast, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Notification published');
      setBroadcast({ title: '', category: 'Events', content: '', type: 'all', department: [], year: [], is_urgent: false });
      fetchDashboard();
    } catch (err) {
      alert(err.response?.data?.message || 'Error');
    }
  };

  const handlePlacementSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/placements`, placement, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Placement published');
      setPlacement({ company: '', role: '', eligibility: '', deadline: '', description: '', is_urgent: false });
      fetchDashboard();
    } catch (err) {
      alert(err.response?.data?.message || 'Error');
    }
  };

  const handleExamSubmit = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/exams`, exam, {
        headers: { Authorization: `Bearer ${localStorage.getItem('token')}` }
      });
      alert('Exam published');
      setExam({ exam_type: 'Internal Test', title: '', content: '', department: [], year: [], is_urgent: false });
      fetchDashboard();
    } catch (err) {
      alert(err.response?.data?.message || 'Error');
    }
  };

  const handleCheckboxChange = (stateObj, setState, field, value) => {
    const list = stateObj[field];
    if (list.includes(value)) {
      setState({ ...stateObj, [field]: list.filter(v => v !== value) });
    } else {
      setState({ ...stateObj, [field]: [...list, value] });
    }
  };

  return (
    <div className="container" style={{ maxWidth: '100%', padding: '0 40px' }}>
      <nav className="dashboard-nav" style={{ background: 'var(--card-bg)', backdropFilter: 'var(--glass-blur)', padding: '20px 30px', borderRadius: '20px', border: '1px solid var(--border)', marginTop: '20px' }}>
        <div className="nav-logo" style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{ width: '32px', height: '32px', background: 'rgba(0, 242, 255, 0.1)', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid var(--accent)' }}>
            <i className="fas fa-signal" style={{ color: 'var(--accent)', fontSize: '14px' }}></i>
          </div>
          <span style={{ fontWeight: '800', letterSpacing: '1px' }}>
            INFOSTREAM <span style={{ fontSize: '10px', background: 'var(--accent)', color: '#000', padding: '2px 8px', borderRadius: '4px', marginLeft: '8px' }}>{role?.toUpperCase()}</span>
          </span>
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

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '30px', marginTop: '30px', alignItems: 'start' }}>
        <aside>
          <div className="glass-card" style={{ padding: '20px' }}>
            <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '20px', paddingLeft: '10px' }}>Command Console</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
              <button className={`nav-tab ${activeTab === 'broadcast-section' ? 'active' : ''}`} onClick={() => handleTabChange('broadcast-section')} style={{ width: '100%', justifyContent: 'flex-start', border: '1px solid transparent', padding: '12px 15px', background: activeTab === 'broadcast-section' ? 'var(--accent)' : 'transparent', color: activeTab === 'broadcast-section' ? '#000' : 'var(--text-muted)' }}>
                <i className="fas fa-broadcast-tower" style={{ width: '20px' }}></i> BROADCAST
              </button>
              <button className={`nav-tab ${activeTab === 'placement-section' ? 'active' : ''}`} onClick={() => handleTabChange('placement-section')} style={{ width: '100%', justifyContent: 'flex-start', border: '1px solid transparent', padding: '12px 15px', background: activeTab === 'placement-section' ? 'var(--accent)' : 'transparent', color: activeTab === 'placement-section' ? '#000' : 'var(--text-muted)' }}>
                <i className="fas fa-briefcase" style={{ width: '20px' }}></i> PLACEMENTS
              </button>
              <button className={`nav-tab ${activeTab === 'exam-section' ? 'active' : ''}`} onClick={() => handleTabChange('exam-section')} style={{ width: '100%', justifyContent: 'flex-start', border: '1px solid transparent', padding: '12px 15px', background: activeTab === 'exam-section' ? 'var(--accent)' : 'transparent', color: activeTab === 'exam-section' ? '#000' : 'var(--text-muted)' }}>
                <i className="fas fa-file-invoice" style={{ width: '20px' }}></i> EXAMS
              </button>
              {role === 'admin' && (
                <>
                  <button className={`nav-tab ${activeTab === 'roster-section' ? 'active' : ''}`} onClick={() => handleTabChange('roster-section')} style={{ width: '100%', justifyContent: 'flex-start', border: '1px solid transparent', padding: '12px 15px', background: activeTab === 'roster-section' ? 'var(--accent)' : 'transparent', color: activeTab === 'roster-section' ? '#000' : 'var(--text-muted)' }}>
                    <i className="fas fa-users-cog" style={{ width: '20px' }}></i> ROSTER
                  </button>
                </>
              )}
            </div>
          </div>
        </aside>

        <main>
          {activeTab === 'broadcast-section' && (
            <div className="admin-section active">
              <div className="glass-card" style={{ padding: '35px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '35px' }}>
                  <div style={{ width: '48px', height: '48px', background: 'var(--accent)', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000' }}>
                    <i className="fas fa-broadcast-tower" style={{ fontSize: '20px' }}></i>
                  </div>
                  <h3 style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '1px' }}>INITIATE BROADCAST</h3>
                </div>

                <form onSubmit={handleBroadcastSubmit}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                    <div className="form-group">
                      <label className="form-label">Title</label>
                      <input value={broadcast.title} onChange={e => setBroadcast({ ...broadcast, title: e.target.value })} placeholder="Enter broadcast title..." required />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Category</label>
                      <select value={broadcast.category} onChange={e => setBroadcast({ ...broadcast, category: e.target.value })} style={{ color: 'var(--accent)', fontWeight: '700' }}>
                        <option value="Events">Events</option>
                        <option value="department">Specific Department/Year</option>
                        <option value="Exam Cell">Exam Cell</option>
                      </select>
                    </div>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Message</label>
                    <textarea value={broadcast.content} onChange={e => setBroadcast({ ...broadcast, content: e.target.value })} rows="4" placeholder="Input detailed transmission data..." required></textarea>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '20px', marginBottom: '25px' }}>
                    <div className="form-group" style={{ marginBottom: '0' }}>
                      <label className="form-label">Send To</label>
                      <select value={broadcast.type} onChange={e => setBroadcast({ ...broadcast, type: e.target.value })} style={{ color: 'var(--accent)', fontWeight: '700' }}>
                        <option value="all">Everyone</option>
                        <option value="department">Sector Restricted (Dept/Phase)</option>
                      </select>
                    </div>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#ff4d4d', fontWeight: '800', fontSize: '11px', cursor: 'pointer', background: 'rgba(255, 77, 77, 0.05)', padding: '8px 15px', borderRadius: '10px', border: '1px solid rgba(255, 77, 77, 0.2)', marginTop: '15px' }}>
                      <input type="checkbox" checked={broadcast.is_urgent} onChange={e => setBroadcast({ ...broadcast, is_urgent: e.target.checked })} style={{ width: 'auto', margin: '0' }} />
                      <i className="fas fa-exclamation-triangle"></i> MARK AS URGENT
                    </label>
                  </div>

                  {broadcast.type === 'department' && (
                    <div style={{ background: 'rgba(255,255,255,0.02)', padding: '25px', borderRadius: '20px', marginBottom: '25px', border: '1px solid var(--border)' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '30px' }}>
                        <div className="form-group" style={{ marginBottom: '0' }}>
                          <label className="form-label">Target Sector(s)</label>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
                            {['CSE', 'ECE', 'IT', 'MECH', 'CIVIL', 'AUTO'].map(dept => (
                              <label key={dept} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', cursor: 'pointer' }}>
                                <input type="checkbox" checked={broadcast.department.includes(dept)} onChange={() => handleCheckboxChange(broadcast, setBroadcast, 'department', dept)} style={{ width: 'auto', margin: '0' }} /> {dept}
                              </label>
                            ))}
                          </div>
                        </div>
                        <div className="form-group" style={{ marginBottom: '0' }}>
                          <label className="form-label">Sector Phase(s)</label>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
                            {['1', '2', '3', '4'].map(yr => (
                              <label key={yr} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', cursor: 'pointer' }}>
                                <input type="checkbox" checked={broadcast.year.includes(yr)} onChange={() => handleCheckboxChange(broadcast, setBroadcast, 'year', yr)} style={{ width: 'auto', margin: '0' }} /> Phase {yr}
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
            </div>
          )}

          {activeTab === 'placement-section' && (
            <div className="admin-section active">
              <div className="glass-card" style={{ padding: '35px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '35px' }}>
                  <div style={{ width: '48px', height: '48px', background: '#adff00', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000' }}>
                    <i className="fas fa-briefcase" style={{ fontSize: '20px' }}></i>
                  </div>
                  <h3 style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '1px' }}>PLACEMENT DISPATCH</h3>
                </div>

                <form onSubmit={handlePlacementSubmit}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                    <div className="form-group">
                      <label className="form-label">Company Name</label>
                      <input value={placement.company} onChange={e => setPlacement({ ...placement, company: e.target.value })} placeholder="e.g. Nexus Dynamics" required />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Job Title</label>
                      <input value={placement.role} onChange={e => setPlacement({ ...placement, role: e.target.value })} placeholder="e.g. Systems Architect" required />
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                    <div className="form-group">
                      <label className="form-label">Eligibility Criteria</label>
                      <input value={placement.eligibility} onChange={e => setPlacement({ ...placement, eligibility: e.target.value })} placeholder="e.g. CGPA > 8.0" required />
                    </div>
                    <div className="form-group">
                      <label className="form-label">Apply By Date</label>
                      <input type="date" value={placement.deadline} onChange={e => setPlacement({ ...placement, deadline: e.target.value })} required />
                    </div>
                  </div>

                  <div className="form-group" style={{ marginBottom: '30px', display: 'flex', alignItems: 'center', gap: '20px' }}>
                    <div style={{ flex: '1' }}>
                      <label className="form-label">Job Description</label>
                      <textarea value={placement.description} onChange={e => setPlacement({ ...placement, description: e.target.value })} rows="3" placeholder="Enter job details..." required></textarea>
                    </div>
                    <label style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#adff00', fontWeight: '800', fontSize: '11px', cursor: 'pointer', background: 'rgba(173, 255, 0, 0.05)', padding: '12px 20px', borderRadius: '12px', border: '1px solid rgba(173, 255, 0, 0.2)', marginTop: '25px' }}>
                      <input type="checkbox" checked={placement.is_urgent} onChange={e => setPlacement({ ...placement, is_urgent: e.target.checked })} style={{ width: 'auto', margin: '0' }} />
                      <i className="fas fa-bolt"></i> MARK AS URGENT
                    </label>
                  </div>

                  <button type="submit" className="submit-btn" style={{ background: '#adff00', boxShadow: '0 4px 15px rgba(173, 255, 0, 0.2)' }}>
                    <i className="fas fa-upload"></i> POST JOB
                  </button>
                </form>
              </div>
            </div>
          )}

          {activeTab === 'exam-section' && (
            <div className="admin-section active">
              <div className="glass-card" style={{ padding: '35px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '15px', marginBottom: '35px' }}>
                  <div style={{ width: '48px', height: '48px', background: '#ffbc00', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#000' }}>
                    <i className="fas fa-file-invoice" style={{ fontSize: '20px' }}></i>
                  </div>
                  <h3 style={{ fontSize: '20px', fontWeight: '800', letterSpacing: '1px' }}>POST EXAM NOTICE</h3>
                </div>

                <form onSubmit={handleExamSubmit}>
                  <div className="form-group">
                    <label className="form-label">Exam Type</label>
                    <select value={exam.exam_type} onChange={e => setExam({ ...exam, exam_type: e.target.value })} style={{ color: '#ffbc00', fontWeight: '700' }}>
                      <option value="Internal Test">Internal Test</option>
                      <option value="University Exam">University Exam</option>
                      <option value="Results">Results</option>
                      <option value="Other">Other</option>
                    </select>
                  </div>

                  <div className="form-group">
                    <label className="form-label">Title</label>
                    <input value={exam.title} onChange={e => setExam({ ...exam, title: e.target.value })} placeholder="e.g. Semester 5 Main Examination" required />
                  </div>

                  <div className="form-group">
                    <label className="form-label">Details</label>
                    <textarea value={exam.content} onChange={e => setExam({ ...exam, content: e.target.value })} rows="3" placeholder="Enter exam details..." required></textarea>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '25px' }}>
                    <div className="form-group" style={{ marginBottom: '0' }}>
                      <label className="form-label">Select Department(s)</label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
                        {['CSE', 'ECE', 'IT', 'MECH', 'CIVIL', 'AUTO'].map(dept => (
                          <label key={dept} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', cursor: 'pointer' }}>
                            <input type="checkbox" checked={exam.department.includes(dept)} onChange={() => handleCheckboxChange(exam, setExam, 'department', dept)} style={{ width: 'auto', margin: '0' }} /> {dept}
                          </label>
                        ))}
                      </div>
                    </div>
                    <div className="form-group" style={{ marginBottom: '0' }}>
                      <label className="form-label">Select Year(s)</label>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginTop: '10px' }}>
                        {['1', '2', '3', '4'].map(yr => (
                          <label key={yr} style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '12px', color: 'var(--text-muted)', cursor: 'pointer' }}>
                            <input type="checkbox" checked={exam.year.includes(yr)} onChange={() => handleCheckboxChange(exam, setExam, 'year', yr)} style={{ width: 'auto', margin: '0' }} /> Phase {yr}
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>

                  <label style={{ display: 'flex', alignItems: 'center', gap: '10px', color: '#ffbc00', fontWeight: '800', fontSize: '11px', cursor: 'pointer', background: 'rgba(255, 188, 0, 0.05)', padding: '12px 20px', borderRadius: '12px', border: '1px solid rgba(255, 188, 0, 0.2)', marginBottom: '30px', width: 'fit-content' }}>
                    <input type="checkbox" checked={exam.is_urgent} onChange={e => setExam({ ...exam, is_urgent: e.target.checked })} style={{ width: 'auto', margin: '0' }} />
                    <i className="fas fa-exclamation-circle"></i> MARK AS URGENT
                  </label>

                  <button type="submit" className="submit-btn" style={{ background: 'transparent', border: '1px solid #ffbc00', color: '#ffbc00', boxShadow: 'none' }}>
                    <i className="fas fa-check-double"></i> POST EXAM NOTICE
                  </button>
                </form>
              </div>
            </div>
          )}

          {activeTab === 'roster-section' && role === 'admin' && (
            <div className="admin-section active">
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '30px' }}>
                <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid var(--accent)' }}>
                  <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>Total Users</div>
                  <div style={{ fontSize: '24px', fontWeight: '900', color: 'var(--text-primary)' }}>{data.users.length} <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '500' }}>Users</span></div>
                </div>
                <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #adff00' }}>
                  <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>Staff Members</div>
                  <div style={{ fontSize: '24px', fontWeight: '900', color: 'var(--text-primary)' }}>{data.users.filter(u => u.role === 'staff').length} <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '500' }}>Staff</span></div>
                </div>
                <div className="glass-card" style={{ padding: '20px', borderLeft: '4px solid #ffbc00' }}>
                  <div style={{ fontSize: '10px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>Registered Students</div>
                  <div style={{ fontSize: '24px', fontWeight: '900', color: 'var(--text-primary)' }}>{data.users.filter(u => u.role === 'student').length} <span style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '500' }}>Identities</span></div>
                </div>
              </div>

              <div className="glass-card" style={{ padding: '35px' }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '35px', flexWrap: 'wrap', gap: '20px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                    <div style={{ width: '42px', height: '42px', background: 'rgba(0, 242, 255, 0.1)', borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent)', border: '1px solid rgba(0, 242, 255, 0.2)' }}>
                      <i className="fas fa-fingerprint" style={{ fontSize: '20px' }}></i>
                    </div>
                    <h3 style={{ fontSize: '18px', fontWeight: '800', letterSpacing: '1px' }}>USER LIST</h3>
                  </div>
                  <div style={{ position: 'relative', width: '300px' }}>
                    <i className="fas fa-search" style={{ position: 'absolute', left: '15px', top: '14px', color: 'var(--text-muted)', fontSize: '12px' }}></i>
                    <input type="text" value={userSearch} onChange={e => setUserSearch(e.target.value)} placeholder="Search users..." style={{ padding: '12px 15px 12px 42px', fontSize: '13px', margin: '0', background: 'var(--input-bg)', border: '1px solid var(--border)' }} />
                  </div>
                </div>
                <div style={{ maxHeight: '600px', overflowY: 'auto', paddingRight: '5px' }}>
                  <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 10px' }}>
                    <thead>
                      <tr style={{ textAlign: 'left' }}>
                        <th style={{ padding: '10px 15px', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: '800', letterSpacing: '1px' }}>Username</th>
                        <th style={{ padding: '10px 15px', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: '800', letterSpacing: '1px' }}>Role</th>
                        <th style={{ padding: '10px 15px', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: '800', letterSpacing: '1px' }}>Department</th>
                        <th style={{ padding: '10px 15px', fontSize: '10px', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: '800', letterSpacing: '1px', textAlign: 'right' }}>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.users.filter(u => u.username.toLowerCase().includes(userSearch.toLowerCase())).map(u => (
                        <tr key={u._id} style={{ background: 'rgba(255,255,255,0.02)', borderRadius: '12px', transition: '0.3s', border: '1px solid transparent' }}>
                          <td style={{ padding: '18px 15px' }}>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '15px' }}>
                              <div style={{ width: '36px', height: '36px', background: 'rgba(255,255,255,0.03)', borderRadius: '10px', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '14px', color: 'var(--text-muted)', border: '1px solid var(--border)' }}>
                                <i className="fas fa-id-badge"></i>
                              </div>
                              <div>
                                <div style={{ fontWeight: '700', fontSize: '15px', color: 'var(--text-primary)' }}>{u.username}</div>
                                <div style={{ display: 'flex', gap: '10px', alignItems: 'center', marginTop: '2px' }}>
                                  <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>ID: {u._id.substring(0, 8)}</span>
                                  {u.phone && (
                                    <span style={{ fontSize: '10px', color: 'var(--accent)', opacity: '0.8' }}>
                                      <i className="fas fa-phone-alt" style={{ fontSize: '8px', marginRight: '3px' }}></i> {u.phone}
                                    </span>
                                  )}
                                </div>
                              </div>
                            </div>
                          </td>
                          <td style={{ padding: '18px 15px' }}>
                            {u.role === 'admin' ? (
                              <span style={{ background: 'rgba(0, 242, 255, 0.1)', color: 'var(--accent)', fontSize: '9px', padding: '5px 12px', borderRadius: '6px', fontWeight: '900', letterSpacing: '1px', border: '1px solid rgba(0, 242, 255, 0.2)' }}>SUPER USER</span>
                            ) : u.role === 'staff' ? (
                              <span style={{ background: 'rgba(173, 255, 0, 0.1)', color: '#adff00', fontSize: '9px', padding: '5px 12px', borderRadius: '6px', fontWeight: '900', letterSpacing: '1px', border: '1px solid rgba(173, 255, 0, 0.2)' }}>STAFF NODE</span>
                            ) : (
                              <span style={{ background: 'rgba(255, 188, 0, 0.1)', color: '#ffbc00', fontSize: '9px', padding: '5px 12px', borderRadius: '6px', fontWeight: '900', letterSpacing: '1px', border: '1px solid rgba(255, 188, 0, 0.2)' }}>STUDENT</span>
                            )}
                          </td>
                          <td style={{ padding: '18px 15px' }}>
                            {u.department ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                                <span style={{ fontSize: '12px', color: '#fff', fontWeight: '700' }}>{u.department}</span>
                                <span style={{ fontSize: '10px', color: 'var(--text-muted)' }}>PHASE {u.year}</span>
                              </div>
                            ) : (
                              <span style={{ fontSize: '11px', color: '#444', fontWeight: '800', letterSpacing: '1px' }}>CORE ACCESS</span>
                            )}
                          </td>
                          <td style={{ padding: '18px 15px', textAlign: 'right' }}>
                            {u.role !== 'admin' ? (
                              <button onClick={async () => {
                                if (window.confirm('Revoke identity?')) {
                                  await axios.delete(`${import.meta.env.VITE_API_URL}/api/auth/users/${u._id}`, { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } });
                                  fetchDashboard();
                                }
                              }} style={{ background: 'rgba(255, 77, 77, 0.05)', border: '1px solid rgba(255, 77, 77, 0.2)', color: '#ff4d4d', padding: '8px 16px', borderRadius: '10px', fontSize: '10px', fontWeight: '900', cursor: 'pointer', transition: '0.3s', letterSpacing: '1px' }}>
                                <i className="fas fa-shield-virus" style={{ marginRight: '5px' }}></i> REVOKE
                              </button>
                            ) : (
                              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '8px', color: '#444', fontWeight: '800', fontSize: '10px', letterSpacing: '1px' }}>
                                <i className="fas fa-lock"></i> IMMUTABLE
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
