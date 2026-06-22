# 3X Cloud — Authentication Gateway

Complete Cloudflare Worker for Discord OAuth2 + Customer role gating + session management.

## Files

| File | Purpose |
|------|---------|
| `worker.js` | Main worker code (no hardcoded secrets) |
| `wrangler.toml` | Worker config (KV binding, no secrets) |
| `package.json` | NPM scripts for local dev & deploy |
| `.gitignore` | Keeps secrets out of Git |

## Setup (Cloudflare Dashboard — Easiest)

1. Go to [dash.cloudflare.com](https://dash.cloudflare.com) → Workers & Pages → your worker
2. **Settings → Variables and Secrets**
   - Add `DISCORD_BOT_TOKEN` → Type: **Secret**
   - Add `DISCORD_CLIENT_SECRET` → Type: **Secret**
3. **Settings → Bindings**
   - Add KV namespace → Name: `SESSIONS`
4. Paste `worker.js` into the editor → **Deploy**

## Setup (Wrangler CLI)

```bash
# Install dependencies
npm install

# Login to Cloudflare
npx wrangler login

# Set secrets
npx wrangler secret put DISCORD_BOT_TOKEN
npx wrangler secret put DISCORD_CLIENT_SECRET

# Update wrangler.toml with your KV namespace ID, then:
npx wrangler deploy
```

## Discord App Settings

- **OAuth2 → Redirects:** `https://3x-cloudxbeta.hmktt22.workers.dev/login.html`
- **Scopes:** `identify`, `guilds`
- **Bot:** Must be in guild `1515906766397898763` with `View Server Insights` permission (to read member roles)

## Important

- **Reset your Discord bot token** if it was ever in Git history.
- This package contains **zero secrets** — configure them in Cloudflare only.
