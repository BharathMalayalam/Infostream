import React, { useState, useEffect } from 'react';
import AuthContext from './authContext';
import axios from '../api/axios';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);   // { role, username } or null
  const [loading, setLoading] = useState(true);

  // On mount: verify cookie session with backend
  useEffect(() => {
    axios
      .get(`${import.meta.env.VITE_API_URL}/api/auth/verify`)
      .then(res => {
        if (res.data.authenticated) {
          setUser({ role: res.data.role, username: res.data.username, id: res.data.id });
        }
      })
      .catch((err) => {
        if (err?.response?.status !== 401) {
          console.warn('Auth verify failed:', err?.message || err);
        }
        setUser(null);
      })
      .finally(() => setLoading(false));
  }, []);

  const login = (userData) => setUser(userData);

  const logout = async () => {
    try {
      await axios.post(`${import.meta.env.VITE_API_URL}/api/auth/logout`);
    } catch {
      console.warn('Logout request failed. Clearing local session state anyway.');
    }
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, login, logout, loading }}>
      {children}
    </AuthContext.Provider>
  );
}
