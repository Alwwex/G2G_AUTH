const form = document.getElementById('login');
const err = document.getElementById('err');

fetch('/api/login-info')
  .then((r) => r.json())
  .then((i) => {
    if (i.totp) {
      document.getElementById('codeWrap').hidden = false;
      form.code.required = true;
    }
  });

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  err.textContent = '';
  const body = Object.fromEntries(new FormData(form));
  const r = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
  if (r.ok) location.href = '/';
  else err.textContent = (await r.json().catch(() => ({}))).error || 'Sign-in failed';
});
