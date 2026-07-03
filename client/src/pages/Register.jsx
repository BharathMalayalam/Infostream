import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import ThemeToggle from '../components/ThemeToggle';

function Register() {
  const [role, setRole] = useState('student');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [phone, setPhone] = useState('');
  const [department, setDepartment] = useState('CSE');
  const [year, setYear] = useState('1');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/register`, {
        username,
        password,
        role,
        phone,
        department,
        year,
      });
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page-centered">
      <div className="auth-container" style={{ maxWidth: 520 }}>
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
          <div style={{ textAlign: 'center', marginBottom: 28 }}>
            <h1 className="logo-text" style={{ fontSize: 24, marginBottom: 6 }}>CREATE ACCOUNT</h1>
            <p className="sub-logo" style={{ marginBottom: 0 }}>Register New User</p>
          </div>

          {error && (
            <div className="alert-error">
              <i className="fas fa-exclamation-circle"></i>
              {error}
            </div>
          )}

          <form onSubmit={handleRegister}>
            {/* Username */}
            <div className="form-group">
              <label className="form-label">Username</label>
              <div className="input-wrapper">
                <i className="fas fa-user input-icon"></i>
                <input
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="Choose your username"
                  required
                  autoComplete="username"
                />
              </div>
            </div>

            {/* Password */}
            <div className="form-group">
              <label className="form-label">Password</label>
              <div className="input-wrapper">
                <i className="fas fa-lock input-icon"></i>
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Create a strong password"
                  required
                  autoComplete="new-password"
                />
              </div>
            </div>

            {/* Phone */}
            <div className="form-group">
              <label className="form-label">Phone Number</label>
              <div className="input-wrapper">
                <i className="fas fa-phone input-icon"></i>
                <input
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  placeholder="e.g. +91 98765 43210"
                  required
                />
              </div>
            </div>

            {/* Account type */}
            <div className="form-group">
              <label className="form-label">Account Type</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{ color: 'var(--accent)', fontWeight: 700 }}
              >
                <option value="student">Student</option>
              </select>
            </div>

            {/* Student fields */}
            {role === 'student' && (
              <div id="studentFields" className="target-fields" style={{ marginBottom: 24 }}>
                <div style={{ fontSize: 10, fontWeight: 800, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: 14 }}>
                  Academic Details
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }} className="form-grid-2">
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Department</label>
                    <select value={department} onChange={(e) => setDepartment(e.target.value)}>
                      {['CSE', 'ECE', 'IT', 'MECH', 'CIVIL', 'AUTO'].map((d) => (
                        <option key={d} value={d}>{d}</option>
                      ))}
                    </select>
                  </div>
                  <div className="form-group" style={{ marginBottom: 0 }}>
                    <label className="form-label">Year</label>
                    <select value={year} onChange={(e) => setYear(e.target.value)}>
                      <option value="1">1st Year</option>
                      <option value="2">2nd Year</option>
                      <option value="3">3rd Year</option>
                      <option value="4">4th Year</option>
                    </select>
                  </div>
                </div>
              </div>
            )}

            <button type="submit" className="submit-btn" disabled={loading}>
              {loading ? (
                <><i className="fas fa-spinner fa-spin"></i> CREATING ACCOUNT...</>
              ) : (
                <><i className="fas fa-user-plus"></i> CREATE ACCOUNT</>
              )}
            </button>
          </form>

          <div style={{ textAlign: 'center', marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
            <p style={{ color: 'var(--text-muted)', fontSize: 13 }}>
              Already have an account?{' '}
              <Link to="/login" style={{ color: 'var(--accent)', fontWeight: 700 }}>
                Login Here
              </Link>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default Register;
