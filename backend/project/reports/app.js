document.getElementById('status')?.addEventListener('click', () => {
  const result = document.getElementById('result');
  if (result) result.textContent = 'The separate app.js asset loaded successfully.';
});
