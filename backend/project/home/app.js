let me;
const $ = (selector) => document.querySelector(selector);
async function loadSession(){ const response = await fetch('/api/me'); if(!response.ok){ location.assign('/login'); return; } me = await response.json(); $('#user-name').textContent = me.username; $('#user-role').textContent = me.role_label; $('#avatar').textContent = me.username.slice(0,1).toUpperCase(); document.querySelectorAll('.admin-link').forEach(link => { if(me.permissions.includes('admin.dashboard.read')) link.hidden = false; }); }
$('#logout').addEventListener('click', async () => { if(!me) return; await fetch('/logout',{method:'POST',headers:{'X-CSRF-Token':me.csrf_token}}); location.assign('/login'); });
$('#menu-btn').addEventListener('click',()=>{$('#sidebar').classList.add('open');$('#scrim').classList.add('open')}); $('#scrim').addEventListener('click',()=>{$('#sidebar').classList.remove('open');$('#scrim').classList.remove('open')});
loadSession();
