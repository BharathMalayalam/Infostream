import React, { useState, useEffect } from 'react';

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

function ThemeToggle() {
  const [theme, setThemeState] = useState('dark');

  useEffect(() => {
    const savedTheme = getCookie('theme') || 'dark';
    setThemeState(savedTheme);
  }, []);

  const setTheme = (newTheme) => {
    document.documentElement.setAttribute('data-theme', newTheme);
    setCookie('theme', newTheme);
    setThemeState(newTheme);
  };

  const toggleTheme = () => {
    setTheme(theme === 'dark' ? 'light' : 'dark');
  };

  return (
    <button className="theme-toggle" id="theme-toggle" title="Toggle Dark/Light Mode" onClick={toggleTheme}>
      <i className={theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon'}></i>
    </button>
  );
}

export default ThemeToggle;
