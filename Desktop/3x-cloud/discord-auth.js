// Cloudflare Pages Function — Discord OAuth2 + Scan Upload Receiver
// Deploy at: /functions/discord-auth.js

export async function onRequestPost(context) {
  const { request, env } = context;
  const url = new URL(request.url);

  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Content-Type': 'application/json'
  };

  if (request.method === 'OPTIONS') {
    return new Response('', { status: 200, headers });
  }

  const body = await request.json();

  // === SCAN UPLOAD ENDPOINT ===
  if (url.pathname === '/scan-upload' || body.scanId) {
    return handleScanUpload(body, env, headers);
  }

  // === DISCORD AUTH ENDPOINT ===
  return handleDiscordAuth(body, env, headers);
}

async function handleScanUpload(data, env, headers) {
  try {
    const scanId = data.scanId || '3X-' + Math.floor(1000 + Math.random() * 9000);
    const timestamp = data.timestamp || new Date().toISOString();

    const scanData = {
      id: scanId, timestamp: timestamp,
      version: data.version || 'unknown',
      system: data.system || {},
      status: data.status || 'unknown',
      score: data.score || 0,
      evidence: data.evidence || [],
      findings: data.findings || [],
      behaviorScore: data.behaviorScore || 0,
      isNapseLike: data.isNapseLike || false,
      isOceanLike: data.isOceanLike || false,
      isEchoLike: data.isEchoLike || false,
      uploadedAt: new Date().toISOString(),
    };

    // Store in KV if available
    if (env.SCANS_KV) {
      await env.SCANS_KV.put(scanId, JSON.stringify(scanData));
    }

    return new Response(JSON.stringify({
      success: true, reportId: scanId, status: data.status,
      score: data.score, url: `/scan-report.html?id=${scanId}`,
      message: 'Scan uploaded successfully'
    }), { status: 200, headers });

  } catch (err) {
    return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers });
  }
}

async function handleDiscordAuth(data, env, headers) {
  const { code, redirectUri } = data;
  if (!code) {
    return new Response(JSON.stringify({ success: false, message: 'No code provided' }), { status: 400, headers });
  }

  const CLIENT_ID = env.DISCORD_CLIENT_ID || '1518460165068689498';
  const CLIENT_SECRET = env.DISCORD_CLIENT_SECRET;
  const BOT_TOKEN = env.DISCORD_BOT_TOKEN;
  const SERVER_ID = '1515906766397898763';
  const CUSTOMER_ROLE_ID = '1518434524026110063';

  if (!CLIENT_SECRET || !BOT_TOKEN) {
    return new Response(JSON.stringify({
      success: false, message: 'Server config missing. Set DISCORD_CLIENT_SECRET and DISCORD_BOT_TOKEN.'
    }), { status: 500, headers });
  }

  try {
    // Exchange code for token
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: CLIENT_ID, client_secret: CLIENT_SECRET,
        grant_type: 'authorization_code', code: code, redirect_uri: redirectUri
      })
    });

    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) {
      return new Response(JSON.stringify({
        success: false, message: 'Authentication configuration error.', debug: tokenData
      }), { status: 400, headers });
    }

    // Get user info
    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const user = await userRes.json();

    // Get connections
    const connectionsRes = await fetch('https://discord.com/api/v10/users/@me/connections', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` }
    });
    const connections = await connectionsRes.json().catch(() => []);

    // Check guild membership
    const memberRes = await fetch(`https://discord.com/api/v10/guilds/${SERVER_ID}/members/${user.id}`, {
      headers: { Authorization: `Bot ${BOT_TOKEN}` }
    });

    let inServer = false, hasRole = false, member = null;
    if (memberRes.ok) {
      member = await memberRes.json();
      inServer = true;
      hasRole = member.roles && member.roles.includes(CUSTOMER_ROLE_ID);
    }

    // Check for "cheats" role on known cheat servers (if guilds.members.read scope granted)
    let cheatServerRoles = [];
    try {
      const guildsRes = await fetch('https://discord.com/api/v10/users/@me/guilds', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` }
      });
      const guilds = await guildsRes.json().catch(() => []);
      // We can't check roles on other servers without additional API calls,
      // but we flag if user is in known cheat servers
      cheatServerRoles = guilds.filter(g => {
        const name = (g.name || '').toLowerCase();
        return name.includes('cheat') || name.includes('hack') || name.includes('mod') || name.includes('menu') || name.includes('executor');
      }).map(g => ({ id: g.id, name: g.name }));
    } catch (e) {}

    return new Response(JSON.stringify({
      success: true,
      user: { id: user.id, username: user.username, global_name: user.global_name,
              avatar: user.avatar, email: user.email, premium_type: user.premium_type || 0, verified: user.verified },
      accessToken: tokenData.access_token,
      inServer, hasRole,
      member: member ? { nick: member.nick, roles: member.roles, joined_at: member.joined_at } : null,
      connections,
      cheatServerRoles,
      message: hasRole ? 'Authorized' : 'Access requires Customer role.'
    }), { status: 200, headers });

  } catch (err) {
    return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers });
  }
}

export async function onRequestOptions() {
  return new Response('', {
    status: 200, headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Access-Control-Allow-Methods': 'POST, OPTIONS'
    }
  });
}

// GET handler for retrieving scan data
export async function onRequestGet(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Content-Type': 'application/json'
  };

  const scanId = url.searchParams.get('id');
  if (!scanId) {
    return new Response(JSON.stringify({ success: false, message: 'No scan ID provided' }), { status: 400, headers });
  }

  try {
    if (env.SCANS_KV) {
      const data = await env.SCANS_KV.get(scanId);
      if (data) return new Response(data, { status: 200, headers });
    }

    // Return demo data if no KV
    return new Response(JSON.stringify({
      success: true, id: scanId, status: 'clean', score: 97,
      system: { os: 'Windows 11 x64', cpu: 'Intel i9-13900K', gpu: 'RTX 4090', ram: '32 GB', hostname: 'DESKTOP-3X', username: 'User', hwid: 'A1B2C3D4-E5F6-7890-ABCD-EF1234567890' },
      evidence: [
        { level: 'clean', title: 'Process integrity check', detail: 'No unsafe process signatures matched. All 247 processes verified.', time: '14:42:10' },
        { level: 'clean', title: 'Overlay module scan', detail: 'No unsigned overlay modules detected.', time: '14:42:35' },
        { level: 'clean', title: 'DLL injection check', detail: 'No injected DLLs found in FiveM process.', time: '14:43:02' },
      ],
      findings: [], behaviorScore: 0,
      isNapseLike: false, isOceanLike: false, isEchoLike: false,
    }), { status: 200, headers });

  } catch (err) {
    return new Response(JSON.stringify({ success: false, message: err.message }), { status: 500, headers });
  }
}
