let me; const $ = s => document.querySelector(s);
async function load(){ const res = await fetch('/api/me'); if(!res.ok){location.assign('/login');return;} me = await res.json(); $('#user-name').textContent=me.username; $('#user-role').textContent=me.role_label; $('#avatar').textContent=me.username.slice(0,1).toUpperCase(); if(me.permissions.includes('admin.dashboard.read')) $('#admin-link').hidden=false; }
$('#logout').addEventListener('click',async()=>{if(me) await fetch('/logout',{method:'POST',headers:{'X-CSRF-Token':me.csrf_token}});location.assign('/login')}); load();
