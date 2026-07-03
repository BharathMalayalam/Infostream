import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useLocation } from 'react-router-dom';
import axios from 'axios';
import ThemeToggle from '../components/ThemeToggle';
import useAuth from '../context/useAuth';

function Login() {
  const [role, setRole] = useState('student');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();
  const location = useLocation();
  const { login, user } = useAuth();

  // If already logged in, redirect to correct page immediately
  useEffect(() => {
    if (user) {
      if (user.role === 'admin' || user.role === 'staff') {
        navigate('/admin', { replace: true });
      } else {
        navigate('/student', { replace: true });
      }
    }
  }, [user, navigate]);

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const r = params.get('role');
    if (r === 'admin' || r === 'student' || r === 'staff') setRole(r);
  }, [location]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await axios.post(
        `${import.meta.env.VITE_API_URL}/api/auth/login`,
        { username, password, role }
      );
      // Save authenticated user state in AuthContext
      login({ role: res.data.role, username: res.data.username, id: res.data.id });
    } catch (err) {
      setError(err.response?.data?.message || 'Login failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const getSubmitStyle = () => {
    if (role === 'admin') return { background: 'var(--accent-secondary)', boxShadow: '0 4px 20px rgba(173,255,0,0.25)' };
    if (role === 'staff') return { background: '#adff00', boxShadow: '0 4px 20px rgba(173,255,0,0.25)' };
    return {};
  };

  const roleLabels = {
    student: { icon: 'fa-user-graduate', text: 'STUDENT' },
    staff:   { icon: 'fa-user-tie',      text: 'STAFF'   },
    admin:   { icon: 'fa-user-shield',   text: 'ADMIN'   },
  };

  return (
    <div className="page-centered">
      <div className="auth-container">
        {/* Top bar */}
        <div className="auth-header">
          <div className="brand-logo" style={{ marginBottom: 0, width: 44, height: 44, borderRadius: 12 }}>
            <i className="fas fa-signal" style={{ fontSize: 18 }}></i>
          </div>
          <div className="auth-header-actions">
            <ThemeToggle />
            <Link to="/" className="home-btn">
              <i className="fas fa-home"></i>
              <span>HOME</span>
            </Link>
          </div>
        </div>

        {/* Card */}
        <div className="glass-card">
          <div style={{ textAlign: 'center', marginBottom: 32 }}>
            <h1 className="logo-text" style={{ fontSize: 26, marginBottom: 6 }}>SIGN IN</h1>
            <p className="sub-logo" style={{ marginBottom: 0 }}>Access Your Account</p>
          </div>

          {/* Error */}
          {error && (
            <div className="alert-error">
              <i className="fas fa-exclamation-circle"></i>
              {error}
            </div>
          )}

          {/* Role toggle */}
          <div className="role-toggle">
            {['student', 'staff', 'admin'].map((r) => (
              <button
                key={r}
                type="button"
                className={`role-btn ${role === r ? 'active' : ''}`}
                onClick={() => setRole(r)}
              >
                <i className={`fas ${roleLabels[r].icon}`}></i>
                {roleLabels[r].text}
              </button>
            ))}
          </div>

          <form onSubmit={handleLogin}>
            <div className="form-group">
              <label className="form-label">Username</label>
              <div className="input-wrapper">
                <i className="fas fa-user input-icon"></i>
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Enter your username"
                  required
                  autoComplete="username"
                />
              </div>
            </div>

            <div className="form-group" style={{ marginBottom: 28 }}>
              <label className="form-label">Password</label>
              <div className="input-wrapper">
                <i className="fas fa-lock input-icon"></i>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  required
                  autoComplete="current-password"
                />
              </div>
            </div>

            <button type="submit" className="submit-btn" style={getSubmitStyle()} disabled={loading}>
              {loading ? (
                <><i className="fas fa-spinner fa-spin"></i> SIGNING IN...</>
              ) : role === 'admin' ? (
                <>LOGIN AS ADMIN <i className="fas fa-shield-alt"></i></>
              ) : role === 'staff' ? (
                <>LOGIN AS STAFF <i className="fas fa-user-tie"></i></>
              ) : (
                <>LOGIN <i className="fas fa-arrow-right"></i></>
              )}
            </button>
          </form>

          <div style={{ textAlign: 'center', marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              New user?{' '}
              <Link to="/register" style={{ color: 'var(--accent)', fontWeight: 700 }}>
                Create Account
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Login;
