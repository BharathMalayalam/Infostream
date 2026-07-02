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
  
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/register`, { 
        username, password, role, phone, department, year 
      });
      navigate('/login');
    } catch (err) {
      setError(err.response?.data?.message || 'Registration failed');
    }
  };

  return (
    <div className="container" style={{ maxWidth: '500px' }}>
      <div style={{ position: 'absolute', top: '30px', right: '30px', display: 'flex', gap: '15px' }}>
        <ThemeToggle />
        <Link to="/" className="logout-link" style={{ background: 'rgba(0, 242, 255, 0.1)', color: 'var(--accent)', padding: '10px 20px', borderRadius: '12px', transition: '0.3s', fontSize: '13px', fontWeight: '700' }}>
          <i className="fas fa-home"></i> HOME
        </Link>
      </div>
      
      <div className="glass-card">
        <div style={{ textAlign: 'center', marginBottom: '30px' }}>
          <h2 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '1px', marginBottom: '8px' }}>CREATE ACCOUNT</h2>
          <p style={{ color: 'var(--accent)', fontSize: '11px', fontWeight: '700', textTransform: 'uppercase', letterSpacing: '3px' }}>Register New User</p>
        </div>

        {error && (
          <div style={{ color: '#ff4d4d', background: 'rgba(255, 77, 77, 0.1)', padding: '12px', borderRadius: '12px', marginBottom: '20px', textAlign: 'center', fontSize: '13px', fontWeight: '600', border: '1px solid rgba(255, 77, 77, 0.2)' }}>
            <i className="fas fa-exclamation-circle" style={{ marginRight: '8px' }}></i> {error}
          </div>
        )}

        <form onSubmit={handleRegister}>
          <div className="form-group">
            <label className="form-label">Username</label>
            <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Choose your username" required />
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Create a password" required />
          </div>

          <div className="form-group">
            <label className="form-label">Phone Number</label>
            <input value={phone} onChange={e => setPhone(e.target.value)} placeholder="e.g. +91 98765 43210" required />
          </div>

          <div className="form-group">
            <label className="form-label">Account Type</label>
            <select value={role} onChange={e => setRole(e.target.value)} style={{ color: 'var(--accent)', fontWeight: '700' }}>
              <option value="student">Student</option>
            </select>
          </div>

          {role === 'student' && (
            <div id="studentFields" style={{ background: 'rgba(255, 255, 255, 0.02)', padding: '25px', borderRadius: '20px', marginBottom: '30px', border: '1px solid var(--border)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                <div className="form-group" style={{ marginBottom: '0' }}>
                  <label className="form-label">Department</label>
                  <select value={department} onChange={e => setDepartment(e.target.value)}>
                    <option value="CSE">CSE</option>
                    <option value="ECE">ECE</option>
                    <option value="IT">IT</option>
                    <option value="MECH">MECH</option>
                    <option value="CIVIL">CIVIL</option>
                    <option value="AUTO">AUTO</option>
                  </select>
                </div>
                <div className="form-group" style={{ marginBottom: '0' }}>
                  <label className="form-label">Year</label>
                  <select value={year} onChange={e => setYear(e.target.value)}>
                    <option value="1">1st Year</option>
                    <option value="2">2nd Year</option>
                    <option value="3">3rd Year</option>
                    <option value="4">4th Year</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          <button type="submit" className="submit-btn">
            <i className="fas fa-user-plus"></i> CREATE ACCOUNT
          </button>
        </form>

        <div style={{ textAlign: 'center', marginTop: '30px', borderTop: '1px solid var(--border)', paddingTop: '20px' }}>
          <p style={{ color: 'var(--text-muted)', fontSize: '13px' }}>
            Already have an account? <Link to="/login" className="logout-link" style={{ display: 'inline', color: 'var(--accent)' }}>Login Here</Link>
          </p>
        </div>
      </div>
    </div>
  );
}

export default Register;
