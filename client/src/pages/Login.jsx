import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import ThemeToggle from '../components/ThemeToggle';

function Login() {
  const [role, setRole] = useState('student');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const r = params.get('role');
    if (r === 'admin' || r === 'student') {
      setRole(r);
    }
  }, [location]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const res = await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/login`, { username, password, role });
      localStorage.setItem('token', res.data.token);
      localStorage.setItem('role', res.data.role);
      
      if (res.data.role === 'admin' || res.data.role === 'staff') {
        navigate('/admin');
      } else {
        navigate('/student');
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed');
    }
  };

  const getSubmitBtnStyle = () => {
    if (role === 'admin') return { background: 'var(--accent-secondary)', boxShadow: '0 4px 15px rgba(173, 255, 0, 0.2)' };
    if (role === 'staff') return { background: '#adff00', boxShadow: '0 4px 15px rgba(173, 255, 0, 0.2)' };
    return { background: 'var(--accent)', boxShadow: '0 4px 15px rgba(0, 242, 255, 0.2)' };
  };

  return (
    <div className="container" style={{ maxWidth: '450px' }}>
      <div style={{ position: 'absolute', top: '30px', right: '30px', display: 'flex', gap: '15px' }}>
        <ThemeToggle />
        <Link to="/" className="logout-link" style={{ background: 'rgba(0, 242, 255, 0.1)', color: 'var(--accent)', padding: '10px 20px', borderRadius: '12px', transition: '0.3s', fontSize: '13px', fontWeight: '700' }}>
          <i className="fas fa-home"></i> HOME
        </Link>
      </div>
      <div className="glass-card">
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center', width: '64px', height: '64px', background: 'rgba(0, 242, 255, 0.1)', borderRadius: '16px', border: '1px solid var(--accent)', marginBottom: '20px' }}>
            <i className="fas fa-signal" style={{ fontSize: '24px', color: 'var(--accent)' }}></i>
          </div>
          <h1 className="logo-text" style={{ fontSize: '24px', letterSpacing: '2px' }}>LOGIN</h1>
          <p className="sub-logo" style={{ color: 'var(--accent)', marginBottom: '0' }}>Access Your Account</p>
        </div>

        {error && (
          <div style={{ color: '#ff4d4d', background: 'rgba(255, 77, 77, 0.1)', padding: '12px', borderRadius: '12px', marginBottom: '20px', textAlign: 'center', fontSize: '13px', fontWeight: '600', border: '1px solid rgba(255, 77, 77, 0.2)' }}>
            <i className="fas fa-exclamation-circle" style={{ marginRight: '8px' }}></i> {error}
          </div>
        )}

        <div className="role-toggle" style={{ marginBottom: '30px' }}>
          <button type="button" className={`role-btn ${role === 'student' ? 'active' : ''}`} onClick={() => setRole('student')}>
            <i className="fas fa-user-graduate"></i> STUDENT
          </button>
          <button type="button" className={`role-btn ${role === 'staff' ? 'active' : ''}`} onClick={() => setRole('staff')}>
            <i className="fas fa-user-tie"></i> STAFF
          </button>
          <button type="button" className={`role-btn ${role === 'admin' ? 'active' : ''}`} onClick={() => setRole('admin')}>
            <i className="fas fa-user-shield"></i> ADMIN
          </button>
        </div>

        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input type="text" value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" required />
          </div>

          <div className="form-group" style={{ marginBottom: '30px' }}>
            <label className="form-label">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" required />
          </div>

          <button type="submit" className="submit-btn" style={getSubmitBtnStyle()}>
            {role === 'admin' ? <>LOGIN AS ADMIN <i className="fas fa-shield-alt"></i></> :
             role === 'staff' ? <>LOGIN AS STAFF <i className="fas fa-user-tie"></i></> :
             <>LOGIN <i className="fas fa-arrow-right"></i></>}
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '30px', borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
            New user? <Link to="/register" className="logout-link" style={{ display: 'inline', color: 'var(--accent)' }}>Create Account</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Login;
