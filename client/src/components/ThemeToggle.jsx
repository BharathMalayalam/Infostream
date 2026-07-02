import React, { useState, useEffect } from 'react';

function ThemeToggle() {
  const [theme, setThemeState] = useState(localStorage.getItem('theme') || 'dark');

  const setTheme = (newTheme) => {
    document.documentElement.setAttribute('data-theme', newTheme);
    localStorage.setItem('theme', newTheme);
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
