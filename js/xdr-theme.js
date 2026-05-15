(function () {
  const STORAGE_KEY = 'xdr_ui_prefs';
  const THEME_EVENT = 'xdr-theme-change';

  function readTheme() {
    try {
      const prefs = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
      return prefs.theme === 'dark-mode' || prefs.theme === 'cyber-mode' ? 'dark-mode' : 'light';
    } catch (_err) {
      return 'light';
    }
  }

  function writeTheme(theme) {
    try {
      const prefs = JSON.parse(localStorage.getItem(STORAGE_KEY) || '{}');
      prefs.theme = theme;
      localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch (_err) {
      // Ignore storage failures; the visible theme still changes for this page.
    }
  }

  function updateButtons(theme) {
    document.querySelectorAll('[data-xdr-theme-toggle]').forEach((button) => {
      const dark = theme === 'dark-mode';
      button.classList.toggle('active', dark);
      button.setAttribute('aria-label', dark ? 'Enable light mode' : 'Enable dark mode');
      button.setAttribute('title', dark ? 'Switch to light mode' : 'Switch to dark mode');
    });
  }

  function applyTheme(theme, persist) {
    document.body.dataset.theme = theme;
    updateButtons(theme);
    if (persist) writeTheme(theme);
    window.dispatchEvent(new CustomEvent(THEME_EVENT, { detail: { theme } }));
  }

  function makeToggle() {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'theme-toggle-btn xdr-floating-theme-toggle';
    button.setAttribute('data-xdr-theme-toggle', '');
    button.innerHTML = [
      '<svg class="icon-moon" viewBox="0 0 24 24" fill="none" aria-hidden="true">',
      '<path d="M20 14.2A8 8 0 1 1 9.8 4a6.5 6.5 0 1 0 10.2 10.2Z" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>',
      '</svg>',
      '<svg class="icon-sun" viewBox="0 0 24 24" fill="none" aria-hidden="true">',
      '<circle cx="12" cy="12" r="4" stroke="currentColor" stroke-width="1.8"/>',
      '<path d="M12 2v2.4M12 19.6V22M4.9 4.9l1.7 1.7M17.4 17.4l1.7 1.7M2 12h2.4M19.6 12H22M4.9 19.1l1.7-1.7M17.4 6.6l1.7-1.7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>',
      '</svg>'
    ].join('');
    document.body.appendChild(button);
  }

  window.XDRToolsTheme = { applyTheme, readTheme };

  document.addEventListener('DOMContentLoaded', () => {
    if (!document.querySelector('[data-xdr-theme-toggle]')) {
      const existingThemeButton = document.getElementById('themeBtn');
      if (existingThemeButton) existingThemeButton.setAttribute('data-xdr-theme-toggle', '');
      else makeToggle();
    }
    applyTheme(readTheme(), false);
    document.addEventListener('click', (event) => {
      const button = event.target.closest('[data-xdr-theme-toggle]');
      if (!button) return;
      const next = document.body.dataset.theme === 'dark-mode' ? 'light' : 'dark-mode';
      applyTheme(next, true);
    });
  });
})();
