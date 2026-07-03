import React, { useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import IndexPage from './pages/Index';
import Login from './pages/Login';
import Register from './pages/Register';
import AdminDashboard from './pages/AdminDashboard';
import StudentDashboard from './pages/StudentDashboard';
import { AuthProvider, useAuth } from './context/AuthContext';

function getCookie(name) {
  const value = `; ${document.cookie}`;
  const parts = value.split(`; ${name}=`);
  if (parts.length === 2) return parts.pop().split(';').shift();
  return null;
}

// Protected Route helper component
function ProtectedRoute({ children, allowedRoles }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="page-centered">
        <div style={{ color: 'var(--accent)', fontSize: '20px', fontWeight: '800' }}>
          <i className="fas fa-spinner fa-spin" style={{ marginRight: '10px' }}></i>
          VERIFYING SESSION...
        </div>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(user.role)) {
    return <Navigate to="/" replace />;
  }

  return children;
}

function AppContent() {
  useEffect(() => {
    // Initialize theme from cookie or default to dark
    const savedTheme = getCookie('theme') || 'dark';
    document.documentElement.setAttribute('data-theme', savedTheme);
  }, []);

  return (
    <Router>
      <Routes>
        <Route path="/" element={<IndexPage />} />
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route 
          path="/admin" 
          element={
            <ProtectedRoute allowedRoles={['admin', 'staff']}>
              <AdminDashboard />
            </ProtectedRoute>
          } 
        />
        <Route 
          path="/student" 
          element={
            <ProtectedRoute allowedRoles={['student']}>
              <StudentDashboard />
            </ProtectedRoute>
          } 
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Router>
  );
}

function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}

export default App;
