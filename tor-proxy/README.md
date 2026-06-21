# HuggingClaw Tor Proxy

A standalone Docker image that runs **Tor SOCKS5** + **WebSocket/HTTP CONNECT relay** on a single port.

Routes all upstream traffic through Tor exit nodes, providing **rotating source IPs** for API calls. Deployed on **Render free tier** (no credit card required) to bypass HF Spaces restrictions and avoid IP-based rate limiting on LLM API providers like opencode.ai.

## How It Works

```
Your HF Space (HuggingClaw)
  └── cloudflare-proxy.js
       └── socks5://tor-proxy.onrender.com:10000
            └── Tor SOCKS5 :9150
                 └── opencode.ai (random exit IP per request)
```

- Single port (10000) handles: **SOCKS5**, **HTTP CONNECT**, **WebSocket relay**
- All upstream traffic goes through Tor SOCKS5 → different exit IP per connection
- Health check at `GET /health`

## Deploy to Render (Free, No Credit Card)

### 1. Push to GitHub

```bash
cd tor-proxy/
git init
git add .
git commit -m "feat: Tor SOCKS5 relay for IP rotation"
# Create a repo on GitHub, then:
git remote add origin https://github.com/YOUR_USER/huggingclaw-tor-proxy.git
git push -u origin main
```

### 2. Deploy on Render

1. Go to [dashboard.render.com](https://dashboard.render.com) → **New +** → **Web Service**
2. Connect your `huggingclaw-tor-proxy` GitHub repo
3. Configure:
   - **Name:** `huggingclaw-tor-proxy`
   - **Environment:** `Docker`
   - **Region:** Any (closest to you)
   - **Branch:** `main`
   - **Health Check Path:** `/health`
   - **Auto-Deploy:** ✅ Yes
4. Click **Create Web Service** — Render builds and deploys (3-5 min)

You'll get a URL like: `https://huggingclaw-tor-proxy.onrender.com`

### 3. Set up Keepalive (Prevents Sleep)

Render free tier spins down after **15 minutes idle**. Use cron-job.org to ping every 10 min:

1. Go to [cron-job.org](https://cron-job.org) → Sign up (free, no CC)
2. Create a cron job:
   - **URL:** `https://huggingclaw-tor-proxy.onrender.com/health`
   - **Schedule:** Every 10 minutes
   - **Save**

Alternatively, use [UptimeRobot](https://uptimerobot.com/) (free, 50 monitors).

### 4. Configure HuggingClaw

Set these in your HF Space **Secrets**:

```
SOCKS5_PROXY_URL=socks5://huggingclaw-tor-proxy.onrender.com:10000
SOCKS5_PROXY_DOMAINS=opencode.ai
```

Restart the HuggingClaw Space. Check logs for:
```
Proxy     : socks5://huggingclaw-tor-proxy.onrender.com:10000 → opencode.ai
[hc-proxy] SOCKS5 routing: opencode.ai → huggingclaw-tor-proxy.onrender.com:10000
```

## Verification

```bash
# Test SOCKS5 through Tor
curl -x socks5h://huggingclaw-tor-proxy.onrender.com:10000 https://httpbin.org/ip
# Run it a few times — should show different Tor exit IPs

# Test health endpoint
curl https://huggingclaw-tor-proxy.onrender.com/health
# → {"status":"ok","tor":true,"torPort":9150,"port":10000}
```

## Architecture

| Component | What |
|-----------|------|
| `Dockerfile` | Alpine 3.19 + Tor + Node.js (no deps) |
| `index.js` | SOCKS5 chain + WebSocket relay via Tor (~310 lines, pure Node.js stdlib) |
| `package.json` | No external dependencies |

**Protocol detection** on port 10000:
- First byte `0x05` → SOCKS5
- First byte `C` → HTTP CONNECT
- Contains `Upgrade: websocket` → WebSocket relay

All protocols chain through `socks5ViaTor()` → Tor SOCKS5 :9150.

## Rollback

1. Remove `SOCKS5_PROXY_URL` and `SOCKS5_PROXY_DOMAINS` from HF Space secrets
2. Restart HF Space — reverts to direct connections
3. Delete the Render Web Service from dashboard
4. Delete the cron-job.org job
