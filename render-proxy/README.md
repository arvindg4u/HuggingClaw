# HuggingClaw Render Proxy

Telegram + WhatsApp proxy for HuggingClaw on HF Spaces. Deploy on **Render free tier**.

## Why

HF Spaces blocks outbound connections to Telegram and WhatsApp servers. This proxy runs on Render (which has unfettered internet access) and relays traffic between HF Spaces and Telegram/WhatsApp.

## Deploy on Render

1. **Fork or push this directory** to a GitHub repo
2. On [Render Dashboard](https://dashboard.render.com), click **New + → Web Service**
3. Connect your repo, set:
   - **Name**: `huggingclaw-proxy` (or any name)
   - **Root Directory**: `render-proxy`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
4. **Free plan** — Render sleeps after 15 min idle. Set up a cron ping (below) to keep it awake.

Or use Docker:
```
docker build -t huggingclaw-proxy ./render-proxy
docker run -p 10000:10000 huggingclaw-proxy
```

## Endpoints

| Path | Purpose |
|------|---------|
| `/telegram/*` | Telegram Bot API proxy → `api.telegram.org/*` |
| `/whatsapp/*` | WhatsApp Web HTTP proxy |
| `/whatsapp-ws` | WhatsApp WebSocket relay |
| `/health` | Health check JSON (`status: ok`) |

## Update HF Space Secrets

Add these to your HF Space secrets:

```bash
# Tell HuggingClaw to route Telegram through this proxy:
TELEGRAM_API_BASE=https://your-proxy.onrender.com/telegram

# Tell HuggingClaw to route WhatsApp through this proxy:
# Update cloudflare-proxy.js or ROUTE_TARGETS as needed
```

## Cron Ping (Keep Alive)

Render free tier sleeps after 15 min of inactivity. Set up a cron job to ping every 10 min:

```bash
# On any server with cron:
curl -s https://your-proxy.onrender.com/health
```

Or use [UptimeRobot](https://uptimerobot.com) (free) or [cron-job.org](https://cron-job.org) (free) to hit `/health` every 10 minutes.

## Verify

```bash
# Test Telegram proxy
curl -s https://your-proxy.onrender.com/health

# Test Telegram API reachability
curl -s https://your-proxy.onrender.com/telegram/botYOUR_TOKEN/getMe
```
