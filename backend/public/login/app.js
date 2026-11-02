if (!window.__aegisLoginBound) {
  window.__aegisLoginBound = true;
  const form = document.getElementById('loginForm');
  const username = document.getElementById('username');
  const pass = document.getElementById('password');
  const eye = document.getElementById('eye');
  const error = document.getElementById('loginError');
  const button = form.querySelector('.login');

  function togglePassword() {
    const showing = pass.type === 'password';
    pass.type = showing ? 'text' : 'password';
    eye.textContent = showing ? 'HIDE' : 'SHOW';
    eye.setAttribute('aria-label', showing ? 'Hide password' : 'Show password');
  }

  eye.addEventListener('click', togglePassword);
  eye.addEventListener('keydown', (event) => {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      togglePassword();
    }
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    button.disabled = true;
    button.textContent = 'Signing in';
    try {
      const response = await fetch('/login', {
        method: 'POST',
        credentials: 'include',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: username.value.trim(), password: pass.value })
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'Unable to sign in');
      window.location.assign(data.redirect || '/home');
    } catch (err) {
      error.textContent = err.message;
      error.hidden = false;
      button.disabled = false;
      button.textContent = 'Sign in';
    }
  });
}
