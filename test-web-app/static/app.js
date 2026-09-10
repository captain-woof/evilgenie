// Dashboard page: verifies bearer token and loads the profile.
fetch('/api/session', {
  headers: { 'Authorization': 'Bearer ' + localStorage.getItem('session_token') }
})
  .then(r => r.json())
  .then(d => {
    document.getElementById('welcome').textContent =
      d.authenticated ? 'Welcome, ' + d.display_name : 'Not authenticated';
  });

fetch('/api/profile?include=settings&format=full')
  .then(r => r.json())
  .then(d => {
    document.getElementById('profile').textContent = JSON.stringify(d, null, 2);
  });
