import React from 'react';
import { Link } from 'react-router-dom';
import ThemeToggle from '../components/ThemeToggle';

function Index() {
  return (
    <div className="container" style={{ maxWidth: '900px' }}>
      <div style={{ position: 'absolute', top: '30px', right: '30px', display: 'flex', gap: '15px' }}>
        <ThemeToggle />
      </div>
      <header style={{ textAlign: 'center', marginBottom: '60px' }}>
        <div style={{
          display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
          width: '80px', height: '80px', background: 'rgba(0, 242, 255, 0.1)',
          borderRadius: '20px', border: '1px solid var(--accent)', marginBottom: '24px'
        }}>
          <i className="fas fa-signal" style={{ fontSize: '32px', color: 'var(--accent)' }}></i>
        </div>
        <h1 className="logo-text" style={{ fontSize: '42px', marginBottom: '8px' }}>INFOSTREAM</h1>
        <p className="sub-logo" style={{ fontSize: '14px', letterSpacing: '6px', color: 'var(--accent)' }}>Student Notification System</p>
        <p style={{ color: 'var(--text-muted)', maxWidth: '500px', margin: '0 auto', fontSize: '16px' }}>
          Stay updated with campus announcements, job placements, and exam schedules. All your important notifications in one place.
        </p>
      </header>

      <div className="portal-grid">
        <Link to="/login?role=admin" className="portal-card">
          <div style={{ position: 'relative' }}>
            <i className="fas fa-user-shield"></i>
            <div style={{
              position: 'absolute', top: '-10px', right: '-10px', width: '12px', height: '12px',
              background: 'var(--accent-secondary)', borderRadius: '50%', boxShadow: '0 0 10px var(--accent-secondary)'
            }}></div>
          </div>
          <span>ADMIN PORTAL</span>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '-10px' }}>Post & Manage Announcements</p>
        </Link>
        <Link to="/login?role=student" className="portal-card">
          <i className="fas fa-user-graduate"></i>
          <span>STUDENT PORTAL</span>
          <p style={{ fontSize: '12px', color: 'var(--text-muted)', marginTop: '-10px' }}>View Your Notifications</p>
        </Link>
      </div>

      <div style={{ textAlign: 'center', marginTop: '60px', padding: '20px', borderTop: '1px solid var(--border)' }}>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px' }}>
          First time here? 
          <Link to="/register" className="logout-link" style={{ display: 'inline-flex', color: 'var(--accent)', marginLeft: '8px' }}>
            Create Account <i className="fas fa-arrow-right" style={{ marginLeft: '8px', fontSize: '10px' }}></i>
          </Link>
        </p>
      </div>
    </div>
  );
}

export default Index;
