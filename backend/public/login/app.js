const form = document.querySelector('#login-form');
const error = document.querySelector('#login-error');
const button = form.querySelector('button');
form.addEventListener('submit', async (event) => {
  event.preventDefault(); error.hidden = true; button.disabled = true;
  const username = form.username.value.trim(); const password = form.password.value;
  try {
    const response = await fetch('/login', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username,password})});
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || 'Unable to sign in.');
    window.location.assign(data.redirect || '/home');
  } catch (err) { error.textContent = err.message; error.hidden = false; button.disabled = false; }
});
