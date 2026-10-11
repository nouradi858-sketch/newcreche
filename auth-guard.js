// Prefer server authentication when the PHP API is configured.
// On static-only Vercel deployments, allow the explicitly marked demo session.
(async function () {
  try {
    const response = await fetch('backend/api.php?action=me', { credentials: 'same-origin', cache: 'no-store' });
    if (response.ok) {
      const data = await response.json();
      if (!data.user || data.user.role !== 'admin') {
        location.replace(data.user && data.user.role === 'parent' ? 'parent.html' : 'login.html');
        return;
      }
      sessionStorage.removeItem('riaya_demo_user');
      window.riayaSession = { user: data.user, csrf: data.csrf };
      document.documentElement.dataset.authenticated = 'true';
      window.dispatchEvent(new CustomEvent('riaya:authenticated', { detail: window.riayaSession }));
      return;
    }
    // If a backend is reachable and rejects the session, do not bypass its response.
    if (response.status !== 404 && response.status !== 405 && response.status !== 500) {
      location.replace('login.html'); return;
    }
  } catch (_) {
    // Static-only hosting has no PHP API; continue to the demo-session check below.
  }
  try {
    const demo = JSON.parse(sessionStorage.getItem('riaya_demo_user') || 'null');
    if (demo && demo.role === 'admin') {
      window.riayaSession = { user: demo, csrf: '' };
      document.documentElement.dataset.authenticated = 'true';
      document.documentElement.dataset.demoMode = 'true';
      window.dispatchEvent(new CustomEvent('riaya:authenticated', { detail: window.riayaSession }));
      return;
    }
  } catch (_) {}
  location.replace('login.html');
})();
