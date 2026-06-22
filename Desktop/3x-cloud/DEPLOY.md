# Deployment Guide — 3X Cloud NAPSE Edition on Cloudflare Pages

## Why Cloudflare Pages?

- **Unlimited bandwidth** — never pay for traffic
- **300+ edge locations** — fastest load times globally
- **Free SSL + custom domain** — included
- **500 builds/month** — plenty for development
- **Pages Functions** — serverless backend included
- **KV Storage** — for scan data persistence

---

## Step 1: Push to GitHub

```bash
cd 3x-cloud-napse
git init
git add .
git commit -m "3X Cloud NAPSE Edition v3.0"
git branch -M main
git remote add origin https://github.com/YOURNAME/3x-cloud-napse.git
git push -u origin main
```

---

## Step 2: Create Cloudflare Pages Project

1. Go to https://dash.cloudflare.com
2. Sign up (free) or log in
3. Click **Workers & Pages** (left sidebar)
4. Click **Create application**
5. Click the **Pages** tab
6. Click **Connect to Git**
7. Select **GitHub** and authorize Cloudflare
8. Select your `3x-cloud-napse` repository
9. Click **Begin setup**

---

## Step 3: Configure Build Settings

| Setting | Value |
|---------|-------|
| Project name | `3x-cloud-napse` |
| Production branch | `main` |
| Build command | `exit 0` (static HTML, no build needed) |
| Build output directory | `.` (root folder) |

Click **Save and Deploy**

Wait ~1 minute. Your site is now live at `https://3x-cloud-napse.pages.dev`

---

## Step 4: Bind KV Namespace

1. Go to your project → **Settings** → **Functions**
2. Under **KV namespace bindings**, click **Add**
3. Variable name: `SCANS_KV`
4. Select or create a KV namespace (e.g., `3x-scans`)
5. Click **Save**

---

## Step 5: Set Environment Variables

1. Go to your project → **Settings** → **Environment variables**
2. Click **Add variables** (Production environment)

| Variable Name | Value |
|---------------|-------|
| `DISCORD_CLIENT_ID` | `1518460165068689498` |
| `DISCORD_SERVER_ID` | `1515906766397898763` |
| `DISCORD_CUSTOMER_ROLE_ID` | `1518434524026110063` |

3. Click **Save**

---

## Step 6: Set Secrets (Encrypted)

### Option A: Wrangler CLI (Recommended)

```bash
# Install Wrangler
npm install -g wrangler

# Login to Cloudflare
wrangler login

# Set secrets
wrangler pages secret put DISCORD_CLIENT_SECRET --project-name=3x-cloud-napse
# Paste your Discord Client Secret

wrangler pages secret put DISCORD_BOT_TOKEN --project-name=3x-cloud-napse
# Paste your Discord Bot Token
```

### Option B: Dashboard

1. Go to your project → **Settings** → **Environment variables**
2. Click **Add variables** → Check **Encrypt**
3. Add:
   - `DISCORD_CLIENT_SECRET` = your secret
   - `DISCORD_BOT_TOKEN` = your bot token
4. Click **Save**

---

## Step 7: Update Discord Redirect URI

1. Go to https://discord.com/developers/applications
2. Select your app → **OAuth2** → **General**
3. Under **Redirects**, add:
   ```
   https://3x-cloud-napse.pages.dev/login.html
   ```
4. Keep localhost for testing:
   ```
   http://localhost:8080/login.html
   ```
5. Click **Save Changes**

---

## Step 8: Redeploy

If you change env vars or secrets, trigger a redeploy:

```bash
git commit --allow-empty -m "trigger redeploy"
git push
```

---

## File Structure

```
3x-cloud-napse/
├── index.html              # Redirect to login
├── login.html              # Discord OAuth2 gateway
├── dashboard.html          # Main dashboard
├── scans.html              # Scan search/filter
├── scan-report.html        # NAPSE-style forensic report
├── scan-simulation.html    # Purple spinner scan UI
├── admin.html              # PIN generator + inventory
├── download.html           # PIN validation + download
├── pricing.html            # 3-tier pricing
├── docs.html               # Setup guide
├── terms.html              # Legal
├── privacy.html            # Privacy
├── cheat-evidence.js       # 40+ cheat signatures
├── behavior-detection.js   # 20+ NAPSE behavior patterns
├── detection_rules.json    # Expanded detection rules
├── scans-data.js           # Demo scan database
├── admin-data.js           # Demo admin data
├── discord-auth.js         # Cloudflare Function (backend)
├── favicon.svg             # 3X logo
├── mark.svg                # 3X mark
├── sitemap.xml
├── robots.txt
└── DEPLOY.md               # This file
```

---

## Troubleshooting

### "Auth error" or 500
- Check that `DISCORD_CLIENT_SECRET` and `DISCORD_BOT_TOKEN` are set as **secrets**, not plain env vars
- Check Functions tab in Cloudflare dashboard for logs
- Ensure bot is in your Discord server with proper permissions

### "Authentication configuration error"
- The redirect URI in Discord app MUST match exactly what's in the OAuth2 URL
- Check for trailing slashes, http vs https

### "Please join our Discord server"
- Bot isn't in your server, or user isn't in the server
- Re-invite bot with `bot` and `guilds.members.read` scopes

### Functions not working
- Ensure `discord-auth.js` is in `functions/` folder at repo root
- Cloudflare Pages auto-detects `functions/` folder
- Check **Functions** tab in dashboard for deployment status

### KV not storing scans
- Ensure `SCANS_KV` binding is created in Pages settings
- Binding name must match exactly: `SCANS_KV`

---

## Custom Domain (Optional)

1. Go to your project → **Custom domains**
2. Click **Set up a custom domain**
3. Enter your domain
4. Follow DNS instructions
5. Update Discord redirect URI to match custom domain

---

## Free Tier Limits

| Limit | Value |
|-------|-------|
| Bandwidth | **Unlimited** |
| Requests | 100,000/day (Functions) |
| KV reads | 100,000/day |
| KV writes | 1,000/day |
| Builds | 500/month |
| Custom domains | Unlimited |
| SSL | Free, auto-renew |

More than enough for a scanner dashboard.

---

## NAPSE PC Check Features

This edition includes:
- **40+ cheat signatures** (Eulen, RedEngine, Phaze, Vortex, Lynx, Brutan, etc.)
- **20+ behavior patterns** (NAPSE, Ocean, Echo detection)
- **AMSI bypass detection**
- **ETW patching detection**
- **WMI tampering detection**
- **PowerShell obfuscation detection**
- **.NET injection detection**
- **APC injection detection**
- **Process hollowing detection**
- **Reflective DLL injection detection**
- **Thread hijacking detection**
- **HWID spoofing artifact detection**
- **Staggered delete detection**
- **Timestamp fixing (timestomp)**
- **Selective cleanup detection**
- **Prefetch gap analysis**
- **USN journal partial wipe detection**
- **Shadow copy manipulation detection**
- **Execution history anomaly (Amcache/BAM/SRUM)**
- **Alternate data stream (ADS) detection**
- **Zero-width character filename detection**
- **Discord cheat server cross-reference**
- **Player history tracking**
- **Repeat offender detection**
