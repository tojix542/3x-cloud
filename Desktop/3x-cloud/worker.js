// ==================== CONFIG ====================
// NO SECRETS HERE. All sensitive values are injected via Worker env vars.
const CONFIG = {
  DISCORD_CLIENT_ID: "1518460165068689498",
  REDIRECT_URI: "https://3x-cloudxbeta.hmktt22.workers.dev/login.html",
  GUILD_ID: "1515906766397898763",
  CUSTOMER_ROLE_ID: "1518434524026110063",
  COOKIE_DOMAIN: "3x-cloudxbeta.hmktt22.workers.dev",
  SESSION_TTL: 172800,
};

// ==================== UTILS ====================
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "https://3x-cloudxbeta.hmktt22.workers.dev",
      "Access-Control-Allow-Credentials": "true",
    },
  });
}

function errorResponse(message, status = 500) {
  return jsonResponse({ success: false, error: message }, status);
}

function setSessionCookie(token) {
  const maxAge = CONFIG.SESSION_TTL;
  return `session=${token}; Max-Age=${maxAge}; Path=/; Domain=${CONFIG.COOKIE_DOMAIN}; HttpOnly; Secure; SameSite=Lax`;
}

function generateSessionToken(userId) {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const random = btoa(String.fromCharCode(...buf)).replace(/[^a-zA-Z0-9]/g, '');
  return `${userId}_${random}_${Date.now()}`;
}

// ==================== DISCORD API ====================
async function discordOAuthExchange(code, env) {
  const body = new URLSearchParams({
    client_id: CONFIG.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code: code,
    redirect_uri: CONFIG.REDIRECT_URI,
    scope: "identify guilds",
  });

  const res = await fetch("https://discord.com/api/v10/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: body.toString(),
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Discord token exchange failed: ${res.status} ${err}`);
  }
  return res.json();
}

async function discordGetUser(accessToken) {
  const res = await fetch("https://discord.com/api/v10/users/@me", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!res.ok) throw new Error("Failed to fetch user");
  return res.json();
}

async function discordGetGuildMember(userId, env) {
  const res = await fetch(
    `https://discord.com/api/v10/guilds/${CONFIG.GUILD_ID}/members/${userId}`,
    {
      headers: { Authorization: `Bot ${env.DISCORD_BOT_TOKEN}` },
    }
  );
  if (res.status === 404) return null;
  if (!res.ok) throw new Error(`Guild member fetch failed: ${res.status}`);
  return res.json();
}

async function checkCheatServerRoles(accessToken) {
  try {
    const res = await fetch("https://discord.com/api/v10/users/@me/guilds", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) return [];
    const guilds = await res.json();
    const knownCheatServers = [];
    const cheatRoles = [];
    for (const guild of guilds) {
      if (knownCheatServers.includes(guild.id)) {
        cheatRoles.push({ guild_id: guild.id, guild_name: guild.name, flag: "known_cheat_server" });
      }
    }
    return cheatRoles;
  } catch (e) {
    return [];
  }
}

// ==================== HTML PAGE ====================
function renderLoginPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>3X Cloud — Authentication Gateway</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:'Segoe UI',system-ui,sans-serif;background:#0a0e12;color:#e2e8f0;display:flex;min-height:100vh}
.left{width:50%;padding:60px;display:flex;flex-direction:column;justify-content:center;background:#0a0e12}
.right{width:50%;padding:60px;display:flex;flex-direction:column;justify-content:center;background:#0d1117}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:40px}
.brand-icon{width:40px;height:40px;background:#10b981;border-radius:8px;display:flex;align-items:center;justify-content:center;font-weight:800;color:#000}
.brand-text h1{font-size:1.25rem;font-weight:700}
.brand-text span{font-size:.75rem;color:#64748b;text-transform:uppercase;letter-spacing:1px}
.badge{display:inline-block;background:#064e3b;color:#10b981;padding:4px 12px;border-radius:20px;font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:24px}
h2{font-size:2.5rem;line-height:1.1;margin-bottom:20px}
h2 .highlight{color:#10b981}
p{color:#64748b;line-height:1.6;margin-bottom:40px;max-width:400px}
.steps{display:flex;flex-direction:column;gap:24px}
.step{display:flex;gap:16px;align-items:flex-start}
.step-num{width:32px;height:32px;border-radius:50%;background:#10b981;color:#000;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:.8rem;flex-shrink:0}
.step h3{font-size:.95rem;margin-bottom:4px}
.step p{font-size:.85rem;margin:0}
.recent{display:flex;gap:8px;margin-top:auto;padding-top:40px;flex-wrap:wrap}
.tag{background:#1e293b;padding:6px 14px;border-radius:6px;font-size:.75rem}
.tag.clean{border:1px solid #10b981;color:#10b981}
.tag.suspicious{border:1px solid #f59e0b;color:#f59e0b}
.tag.threat{border:1px solid #ef4444;color:#ef4444}
.auth-box{max-width:400px;width:100%}
.auth-box h2{font-size:1.5rem;margin-bottom:8px}
.auth-box > p{color:#64748b;font-size:.9rem;margin-bottom:24px}
.alert{padding:20px;border-radius:12px;margin-bottom:24px}
.alert.error{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);color:#fca5a5}
.alert.warn{background:rgba(245,158,11,0.1);border:1px solid rgba(245,158,11,0.3);color:#fcd34d}
.alert h3{font-size:1rem;margin-bottom:6px}
.alert a{color:#10b981;text-decoration:none;font-weight:600}
.alert a:hover{text-decoration:underline}
.discord-btn{width:100%;padding:14px;background:#5865f2;border:none;border-radius:10px;color:#fff;font-weight:600;cursor:pointer;display:flex;align-items:center;justify-content:center;gap:10px;font-size:.95rem;transition:opacity .2s}
.discord-btn:hover{opacity:.9}
.checks{display:flex;flex-direction:column;gap:12px;margin-top:24px}
.check{display:flex;justify-content:space-between;padding:12px 16px;background:#1e293b;border-radius:8px;font-size:.85rem}
.check span:first-child{color:#94a3b8}
.check span:last-child{font-weight:600}
.check .verified{color:#10b981}
.check .pending{color:#64748b}
.footer{margin-top:auto;text-align:center;font-size:.75rem;color:#334155;padding-top:40px}
.footer a{color:#10b981;text-decoration:none}
@media(max-width:900px){body{flex-direction:column}.left,.right{width:100%;padding:30px}}
</style>
</head>
<body>
<div class="left">
  <div class="brand">
    <div class="brand-icon">3X</div>
    <div class="brand-text">
      <h1>3X Cloud</h1>
      <span>Game Forensics</span>
    </div>
  </div>
  <div class="badge">Deep-scan Forensics</div>
  <h2>Detect threats.<br><span class="highlight">Protect</span> your server.</h2>
  <p>Multi-layer 6–8 minute deep-dive inspection. Professional-grade reports for community moderators — generated instantly.</p>
  <div class="steps">
    <div class="step">
      <div class="step-num">01</div>
      <div><h3>Get the signed client</h3><p>Download securely with your session PIN after login.</p></div>
    </div>
    <div class="step">
      <div class="step-num">02</div>
      <div><h3>Run as Administrator</h3><p>No install needed. Launch the scanner with elevated privileges.</p></div>
    </div>
    <div class="step">
      <div class="step-num">03</div>
      <div><h3>Insert your session PIN</h3><p>Authenticate each session with a fresh PIN from your admin.</p></div>
    </div>
    <div class="step">
      <div class="step-num">04</div>
      <div><h3>Review the web report</h3><p>Timestamped findings: clean, suspicious, or threat — right here.</p></div>
    </div>
  </div>
  <div class="recent">
    <span class="tag clean">● 3X-8721 mohssine31 — Clean</span>
    <span class="tag suspicious">● 3X-8718 Razor — Suspicious</span>
    <span class="tag threat">● 3X-8709 Nox — Threat</span>
  </div>
</div>
<div class="right">
  <div class="auth-box">
    <h2>Authentication Gateway</h2>
    <p>Login with Discord. You must hold the <strong>Customer</strong> role in our server to unlock the dashboard.</p>
    <div id="banner"></div>
    <button class="discord-btn" onclick="login()">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor"><path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.248.195.373.292a.077.077 0 0 1-.007.128 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/></svg>
      Continue with Discord
    </button>
    <div class="checks">
      <div class="check"><span>discord_id</span><span class="pending">verified after login</span></div>
      <div class="check"><span>server_check</span><span class="pending">must be in our server</span></div>
      <div class="check"><span>role_check</span><span class="pending">customer role required</span></div>
      <div class="check"><span>session_ttl</span><span>48h</span></div>
    </div>
  </div>
  <div class="footer">
    <p>Not in our Discord? <a href="https://discord.gg/YOUR_INVITE">Join here</a> first.</p>
    <p><a href="#">Pricing</a> · <a href="#">Terms</a> · <a href="#">Privacy</a></p>
    <p style="margin-top:12px">3X CLOUD — GAME FORENSICS PLATFORM</p>
  </div>
</div>
<script>
function login(){
  const clientId = "${CONFIG.DISCORD_CLIENT_ID}";
  const redirect = "${CONFIG.REDIRECT_URI}";
  const scope = "identify%20guilds";
  const url = \`https://discord.com/api/oauth2/authorize?client_id=\${clientId}&redirect_uri=\${encodeURIComponent(redirect)}&response_type=code&scope=\${scope}\`;
  window.location.href = url;
}
const params = new URLSearchParams(window.location.search);
const banner = document.getElementById('banner');
if(params.has('error')){
  if(params.get('error')==='connection'){
    banner.innerHTML = \`<div class="alert error"><h3>⚠ Connection Error</h3><p>Could not connect to auth server. Please try again.</p><a href="https://discord.gg/YOUR_INVITE" target="_blank">Join Discord Server →</a></div>\`;
  } else {
    banner.innerHTML = \`<div class="alert warn"><h3>⚠ Access Restricted</h3><p>You don't have the Customer role yet. Join our Discord and open a support ticket to purchase access.</p><a href="https://discord.gg/YOUR_INVITE" target="_blank">Join Discord Server →</a></div>\`;
  }
}
</script>
</body></html>`;
}

// ==================== WORKER ENTRY ====================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "https://3x-cloudxbeta.hmktt22.workers.dev",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Allow-Credentials": "true",
        },
      });
    }

    try {
      // ---- OAuth2 Callback ----
      if (path === "/login.html" && url.searchParams.has("code")) {
        const code = url.searchParams.get("code");

        let tokenData;
        try {
          tokenData = await discordOAuthExchange(code, env);
        } catch (e) {
          console.error("OAuth exchange failed:", e.message);
          return Response.redirect(`${url.origin}/login.html?error=connection`, 302);
        }

        const accessToken = tokenData.access_token;
        if (!accessToken) {
          return Response.redirect(`${url.origin}/login.html?error=connection`, 302);
        }

        let user;
        try {
          user = await discordGetUser(accessToken);
        } catch (e) {
          console.error("User fetch failed:", e.message);
          return Response.redirect(`${url.origin}/login.html?error=connection`, 302);
        }

        let member;
        try {
          member = await discordGetGuildMember(user.id, env);
        } catch (e) {
          console.error("Guild member fetch failed:", e.message);
          return Response.redirect(`${url.origin}/login.html?error=connection`, 302);
        }

        if (!member) {
          return Response.redirect(`${url.origin}/login.html?error=restricted&reason=not_in_server`, 302);
        }

        const hasCustomerRole = member.roles?.includes(CONFIG.CUSTOMER_ROLE_ID);
        if (!hasCustomerRole) {
          return Response.redirect(`${url.origin}/login.html?error=restricted&reason=no_customer_role`, 302);
        }

        let cheatFlags = [];
        try {
          cheatFlags = await checkCheatServerRoles(accessToken);
        } catch (e) {
          cheatFlags = [];
        }

        const sessionToken = generateSessionToken(user.id);
        const sessionData = {
          user_id: user.id,
          username: user.username,
          discriminator: user.discriminator,
          avatar: user.avatar,
          guild_id: CONFIG.GUILD_ID,
          roles: member.roles || [],
          cheat_flags: cheatFlags,
          created_at: Date.now(),
        };

        if (env.SESSIONS) {
          await env.SESSIONS.put(sessionToken, JSON.stringify(sessionData), {
            expirationTtl: CONFIG.SESSION_TTL,
          });
        }

        return new Response(null, {
          status: 302,
          headers: {
            Location: `${url.origin}/dashboard`,
            "Set-Cookie": setSessionCookie(sessionToken),
            "Cache-Control": "no-store",
          },
        });
      }

      // ---- Login Page ----
      if (path === "/login.html" || path === "/login") {
        return new Response(renderLoginPage(), {
          headers: { "Content-Type": "text/html" },
        });
      }

      // ---- API: Verify Session ----
      if (path === "/api/auth/verify") {
        const cookie = request.headers.get("Cookie") || "";
        const sessionMatch = cookie.match(/session=([^;]+)/);
        if (!sessionMatch) return jsonResponse({ valid: false });

        const sessionToken = sessionMatch[1];
        let sessionData = null;

        if (env.SESSIONS) {
          const raw = await env.SESSIONS.get(sessionToken);
          if (raw) sessionData = JSON.parse(raw);
        }

        if (!sessionData) return jsonResponse({ valid: false });
        return jsonResponse({ valid: true, user: sessionData });
      }

      // ---- API: Scan Status ----
      if (path === "/api/scan/status") {
        const cookie = request.headers.get("Cookie") || "";
        const sessionMatch = cookie.match(/session=([^;]+)/);
        if (!sessionMatch) return errorResponse("Unauthorized", 401);

        const sessionToken = sessionMatch[1];
        let sessionData = null;
        if (env.SESSIONS) {
          const raw = await env.SESSIONS.get(sessionToken);
          if (raw) sessionData = JSON.parse(raw);
        }
        if (!sessionData) return errorResponse("Unauthorized", 401);

        return jsonResponse({
          user_id: sessionData.user_id,
          scan_status: "idle",
          cheat_flags: sessionData.cheat_flags || [],
        });
      }

      return Response.redirect(`${url.origin}/login.html`, 302);

    } catch (err) {
      console.error("Worker unhandled error:", err);
      return Response.redirect(`${url.origin}/login.html?error=connection`, 302);
    }
  },
};
