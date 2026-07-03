import React from 'react';
import { Link } from 'react-router-dom';
import ThemeToggle from '../components/ThemeToggle';

function Index() {
  return (
    <div className="page-centered">
      <div className="portal-section animate-in">
        {/* Header */}
        <header className="portal-header">
          <div style={{ display: 'flex', justifyContent: 'flex-end', marginBottom: '24px' }}>
            <ThemeToggle />
          </div>

          <div style={{ textAlign: 'center' }}>
            <div className="brand-logo" style={{ margin: '0 auto 20px' }}>
              <i className="fas fa-signal"></i>
            </div>
            <h1 className="logo-text">INFOSTREAM</h1>
            <p className="sub-logo">Student Notification System</p>
            <p className="portal-description">
              Stay updated with campus announcements, job placements, and exam
              schedules. All your important notifications in one place.
            </p>
          </div>
        </header>

        {/* Portal Cards */}
        <div className="portal-grid">
          <Link to="/login?role=admin" className="portal-card">
            <div style={{ position: 'relative' }}>
              <i className="fas fa-user-shield"></i>
              <span className="indicator-dot"></span>
            </div>
            <div>
              <span>ADMIN PORTAL</span>
              <p>Post &amp; Manage Announcements</p>
            </div>
          </Link>

          <Link to="/login?role=student" className="portal-card">
            <i className="fas fa-user-graduate"></i>
            <div>
              <span>STUDENT PORTAL</span>
              <p>View Your Notifications</p>
            </div>
          </Link>
        </div>

        {/* Footer */}
        <div className="portal-footer">
          First time here?
          <Link to="/register">
            Create Account &nbsp;<i className="fas fa-arrow-right" style={{ fontSize: '10px' }}></i>
          </Link>
        </div>
      </div>
    </div>
  );
}

export default Index;
