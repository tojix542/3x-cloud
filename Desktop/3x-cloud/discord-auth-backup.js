// Cloudflare Pages Function - handles Discord OAuth2 + role checking
// Deployed at: /discord-auth

export async function onRequestPost(context) {
  const { request, env } = context;

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (request.method === 'OPTIONS') {
    return new Response('', { status: 200, headers });
  }

  const { code, redirectUri } = await request.json();

  if (!code) {
    return new Response(JSON.stringify({ success: false, message: 'No code provided' }), {
      status: 400, headers
    });
  }

  const CLIENT_ID = env.DISCORD_CLIENT_ID;
  const CLIENT_SECRET = env.DISCORD_CLIENT_SECRET;
  const BOT_TOKEN = env.DISCORD_BOT_TOKEN;
  const SERVER_ID = '1515906766397898763';
  const CUSTOMER_ROLE_ID = '1518434524026110063';

  if (!CLIENT_ID || !CLIENT_SECRET || !BOT_TOKEN) {
    return new Response(JSON.stringify({ 
      success: false, 
      message: 'Server config missing. Set DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, DISCORD_BOT_TOKEN in Cloudflare Pages environment variables.' 
    }), { status: 500, headers });
  }

  try {
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return new Response(JSON.stringify({ 
        success: false, 
        message: 'Authentication configuration error. Please contact support.',
        debug: tokenData 
      }), { status: 400, headers });
    }

    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();

    const memberRes = await fetch(`https://discord.com/api/v10/guilds/${SERVER_ID}/members/${user.id}`, {
      headers: { Authorization: `Bot ${BOT_TOKEN}` }
    });

    if (!memberRes.ok) {
      return new Response(JSON.stringify({ 
        success: true, 
        user, 
        accessToken: tokenData.access_token,
        inServer: false, 
        hasRole: false,
        message: 'Please join our Discord server to continue: https://discord.gg/QjzyvHVj79' 
      }), { status: 200, headers });
    }

    const member = await memberRes.json();
    const hasRole = member.roles && member.roles.includes(CUSTOMER_ROLE_ID);

    return new Response(JSON.stringify({
      success: true,
      user,
      accessToken: tokenData.access_token,
      inServer: true,
      hasRole,
      message: hasRole ? 'Authorized' : 'Access requires the Customer role. Open a ticket in our Discord to request access.'
    }), { status: 200, headers });

  } catch (err) {
    return new Response(JSON.stringify({ success: false, message: err.message }), {
      status: 500, headers
    });
  }
}

export async function onRequestOptions() {
  return new Response('', {
    status: 200,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    }
  });
}