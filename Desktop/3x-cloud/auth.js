(function(){
  const login = document.querySelector('[data-login]');
  const logout = document.querySelector('[data-logout]');
  const user = JSON.parse(localStorage.getItem('threex_user') || 'null');

  const urlParams = new URLSearchParams(location.search);
  const code = urlParams.get('code');
  const error = urlParams.get('error');
  const errorDesc = urlParams.get('error_description');

  if (code) {
    exchangeCode(code);
  } else if (error) {
    window.toast?.('Discord auth failed: ' + (errorDesc || error));
    history.replaceState({}, '', location.pathname);
  }

  async function exchangeCode(code) {
    try {
      let apiUrl = '/.netlify/functions/discord-auth';
      const host = location.hostname;

      if (host.includes('vercel.app')) {
        apiUrl = '/api/discord-auth';
      } else if (host.includes('pages.dev')) {
        apiUrl = '/discord-auth';
      } else if (host === 'localhost' || host === '127.0.0.1') {
        window.toast?.('Authenticating... for demo');
        localStorage.setItem('threex_user', JSON.stringify({
          name: 'Staff User',
          id: 'DISCORD-Active',
          avatar: '3X',
          discordId: 'DISCORD-Active',
          accessToken: 'demo'
        }));
        history.replaceState({}, '', location.pathname);
        setTimeout(() => location.href = 'dashboard.html', 600);
        return;
      }

      const res = await fetch(apiUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code, redirectUri: location.origin + location.pathname })
      });
      const data = await res.json();

      if (!data.success) {
        window.toast?.(data.message || 'Authentication failed');
        return;
      }

      if (!data.hasRole) {
        window.toast?.('Access denied. Please ensure you have the Customer role in our Discord server.');
        return;
      }

      localStorage.setItem('threex_user', JSON.stringify({
        name: data.user.username,
        id: data.user.id,
        avatar: data.user.avatar,
        discordId: data.user.id,
        accessToken: data.accessToken
      }));

      window.toast?.('Welcome back, ' + data.user.username);
      history.replaceState({}, '', location.pathname);
      setTimeout(() => location.href = 'dashboard.html', 600);

    } catch (e) {
      console.error(e);
      window.toast?.('Authentication error. Please try again or contact support.');
    }
  }

  document.querySelectorAll('[data-user-name]').forEach(el=>el.textContent = user?.name || 'Guest');
  document.querySelectorAll('[data-user-id]').forEach(el=>el.textContent = user?.discordId || 'Not logged in');

  if(login){
    login.addEventListener('click',()=>{
      const clientId = window.THREEX?.discordClientId;
      const redirectUri = encodeURIComponent(window.THREEX?.discordRedirectUri || location.origin + location.pathname);
      const scope = encodeURIComponent(window.THREEX?.discordScopes || 'identify guilds guilds.members.read');
      const discordUrl = `https://discord.com/oauth2/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&scope=${scope}`;
      location.href = discordUrl;
    });
  }

  if(logout){
    logout.addEventListener('click',()=>{
      localStorage.removeItem('threex_user');
      window.toast?.('Logged out successfully');
      setTimeout(()=>location.reload(), 500);
    });
  }
})();