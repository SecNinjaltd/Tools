(() => {
  'use strict';

  try {
    const storedTextSize = localStorage.getItem('caArchitectTextSize');
    document.documentElement.dataset.textSize = storedTextSize === 'large' ? 'large' : 'standard';

    const storedTheme = localStorage.getItem('caArchitectComplianceTheme');
    if (storedTheme === 'light' || storedTheme === 'dark') {
      document.documentElement.dataset.theme = storedTheme;
    }
  } catch (_) {
    document.documentElement.dataset.textSize = 'standard';
  }
})();
