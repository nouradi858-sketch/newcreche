// Enforce role-based entry to the administration interface.
// The server, not this browser script, remains the authority for permissions.
(async function () {
  try {
    const response = await fetch('backend/api.php?action=me', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok) { location.replace('login.html'); return; }
    const data = await response.json();
    if (!data.user || data.user.role !== 'admin') {
      location.replace(data.user && data.user.role === 'parent' ? 'parent.html' : 'login.html');
      return;
    }
    window.riayaSession = { user: data.user, csrf: data.csrf };
    document.documentElement.dataset.authenticated = 'true';
    window.dispatchEvent(new CustomEvent('riaya:authenticated', { detail: window.riayaSession }));
  } catch (_) {
    // Fail closed: do not show the admin workspace if authentication cannot be verified.
    location.replace('login.html');
  }
})();