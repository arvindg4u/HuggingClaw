# HuggingClaw WireGuard (Proton VPN) Proxy

Routes opencode.ai traffic through **Proton VPN** using `wireproxy` (userspace WireGuard — no kernel module required).

Deploy on **Render free tier** (no credit card). Works on any platform that supports Docker.

## Architecture

```
opencode.ai API call (HF Space)
  → cloudflare-proxy.js → socks5Connect()
  → Proton VPN SOCKS5 :1080 (on Render)
  → Proton VPN exit IP (residential, not blocked)
  → opencode.ai (no Tor/Cloudflare blocks!)
```

## Deploy to Render

### 1. Pull the image

The Docker image `samuelmoraesf/protonvpn-proxy` is pre-built. Go to Render Dashboard:

1. **New +** → **Web Service**
2. **Deploy from Docker Image** → Enter: `samuelmoraesf/protonvpn-proxy:latest`
3. **Name:** `huggingclaw-wg-proxy`
4. **Region:** Any
5. **Branch:** Not needed (Docker image deploy)

### 2. Set Environment Variables

| Variable | Value |
|----------|-------|
| `WG_PRIVATE_KEY` | `wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=` |
| `WG_PEER_PUBLIC_KEY` | `Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=` |
| `WG_ENDPOINT` | `146.70.202.34:51820` |

### 3. Health Check & Port

- **Health Check Path:** `/`
- **Port:** `1080`

### 4. Keep Alive

Render free tier sleeps after 15min. Set up a free cron-job.org:

1. Go to [cron-job.org](https://cron-job.org)
2. Create job: Ping `http://huggingclaw-wg-proxy.onrender.com:1080` every 10 min

## Configure HuggingClaw

Set these secrets in HF Space:

```
ROUTE_ENDPOINT=socks5://huggingclaw-wg-proxy.onrender.com:1080
ROUTE_TARGETS=opencode.ai
```

## How to Add More Servers

For multiple free servers (US, NL, JP), you'd need separate Render services.
