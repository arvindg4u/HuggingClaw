# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# HuggingClaw — Overview

HuggingClaw is a Docker-based deployment of an **OpenClaw** LLM gateway + **JupyterLab** terminal that runs on **HuggingFace Spaces** (free tier: 2 vCPU, 16GB RAM). It provides a 24/7 AI assistant via Telegram, WhatsApp, and Web Control UI, with automatic workspace backup to a private HF Dataset.

**Stack:** Docker, Node.js, Python 3, OpenClaw gateway (Node.js), JupyterLab

**Deployment target:** HuggingFace Spaces Docker runtime (port 7861 exposed)

---

# Architecture

## Entrypoint & Routing

The public endpoint is `health-server.js` (Node.js, port 7861) which acts as a **reverse proxy + dashboard**:

| Path | Backend | Internal Port |
|------|---------|--------------|
| `/` | HuggingClaw dashboard | 7861 |
| `/app/` | OpenClaw Control UI | 7860 |
| `/terminal/` | JupyterLab terminal | 8888 |
| `/health` | Health check endpoint | 7861 |

## Core Files

### Entrypoint
- `Dockerfile` — Multi-stage build: pulls pre-built `ghcr.io/openclaw/openclaw`, adds Node.js 22-slim runtime, system deps, wireproxy, JupyterLab (optional), copies all app files.
- `start.sh` (~1980 lines) — Main startup script. Orchestrates entire boot sequence.

### Reverse Proxy / Dashboard
- `health-server.js` (~1037 lines) — Node.js HTTP server. Reverse-proxies `/app/` to OpenClaw on :7860, `/terminal/` to JupyterLab on :8888, serves dashboard at `/`. Handles auth, session cookies, CORS, sync/uptime status, VPN live tile.

### Network Proxy Layer — Cloudflare Proxy
- `cloudflare-proxy.js` (~1379 lines) — Node.js `--require` preload that patches `http.request`, `https.request`, `fetch`, `net.connect`, `tls.connect` to route blocked domains (Telegram API, opencode.ai, WhatsApp) through a SOCKS5 proxy. Handles Cloudflare Worker proxy fast-path for Telegram. Also provisions and monitors Cloudflare Workers for outbound proxy.

### Network Proxy Layer — Channel-specific Preloads
All loaded via `NODE_OPTIONS` in the Dockerfile. Each patches specific outbound traffic:

- `telegram-proxy.cjs` — Routes Telegram bot API calls through SOCKS5/Cloudflare Worker
- `whatsapp-proxy.cjs` — Routes WhatsApp WebSocket/session traffic through SOCKS5 proxy
- `dns-fix.cjs` — Patches Node.js DNS resolution to use DoH/DoT when native DNS is blocked

### VPN Tunnel — Proton VPN (Main Container)
- `protonvpn-manager.sh` (~303 lines) — Manages a WireGuard VPN tunnel via [wireproxy](https://github.com/octeep/wireproxy) (userspace HTTP CONNECT, no TUN/NET_ADMIN). Built-in 4 Singapore Proton VPN FREE WireGuard configs. Features: auto-start, 30-min IP rotation, 60s health check, auto-rotate after 2 consecutive failures, manual rotate via dashboard button (`/tmp/protonvpn-force-rotate`). Available as a tile on the dashboard.

### SOCKS5 Proxy Pool
- `proxy-pool.py` — Self-rotating SOCKS5 proxy pool. Fetches free SOCKS5 proxies, tests against api.telegram.org, runs local SOCKS5 server on :9050 with auto-rotation every 10 minutes.

### LLM Key Rotation
- `multi-provider-key-rotator.cjs` — Node.js `--require` preload. Intercepts OpenClaw HTTP requests to LLM providers, round-robins API keys from `{PROVIDER}_API_KEYS` env var pools. Handles 429/402 backoff, blacklisting, strikes.

### Persistence / Backup
- `openclaw-sync.py` (~847 lines) — Background sync loop (3 min default). Uploads/restores OpenClaw workspace data, app state, and WhatsApp credentials to/from a private HF Dataset (`huggingclaw-backup`).
- `jupyter-devdata-sync.py` — Syncs JupyterLab root directory devdata to separate HF Dataset (`huggingclaw-devdata`).

### Channel Integrations
- `wa-guardian.js` — WhatsApp session guardian. Monitors OpenClaw gateway via WebSocket for WhatsApp "515 Restart" events, re-pairs credentials automatically.

### SSH/iframe Fixes
- `iframe-fix.cjs` — Node.js preload that patches HTTP `Server.prototype.emit` to strip `X-Frame-Options` and fix CSP `frame-ancestors` for HF Spaces embedding.

### Environment Builder
- `env-builder.html` / `env-builder.js` — Client-side web UI for generating a base64-encoded `HUGGINGCLAW_ENV_BUNDLE` from a form. No server dependency.

### Startup Utility
- `package-manifest.sh` — Generates a package manifest of installed tools and versions on boot, displayed on the dashboard.

### Subprojects (YouTube Transcript Proxy Ecosystem)

Three deployable YouTube transcript proxies that provide MCP-compatible transcript extraction:

**1. `render-youtube-proxy/`** — Docker app for Render free tier. yt-dlp + PO token bypass + WireGuard VPN.
- `app.py` — FastAPI server, uses yt-dlp with multiple player clients (android, tv, ios, web, mweb)
- `wg-manager.sh` (~251 lines) — WireGuard tunnel manager (wireproxy). 4 built-in Proton VPN configs, health checks every 30s, auto-rotate on 2 failures
- `Dockerfile` — Python 3.13-slim + bgutil-ytdlp-pot-provider sidecar for PO token generation
- `keep-alive.js` — Cron script to prevent Render from sleeping
- Endpoints: `/transcript/{id}/text`, `/transcript/{id}`, `/transcripts/{id}`, `/health`, `/tunnel`, `/mcp`

**2. `vercel-youtube-proxy/`** — Vercel serverless function. Uses `youtube-transcript-api` directly.
- `api/index.py` — Serverless handler, MCP + REST endpoints
- Optional WebShare residential proxy support (10 free proxies)
- Endpoints: `/mcp`, `/transcript/{id}/text`

**3. `mcp-servers/youtube-transcript/`** — Standalone local MCP server.
- `server.js` — MCP server using `@modelcontextprotocol/sdk`, fetches transcripts via direct API
- Can be run locally or deployed as a remote MCP endpoint

**Other proxy subprojects:**
- `render-proxy/` — WebSocket-to-TCP relay (SOCKS5 tunnel via Render)
- `vercel-proxy/` — Vercel serverless proxy function

### Other Scripts
- `yt-transcript.py` — Standalone Python script to fetch YouTube transcripts (no server, for CLI use)
- `dns-resolve.py` — Python DNS resolver helper (DoH/DoT)
- `whatsapp-proxy.cjs` — WhatsApp WebSocket/session proxy preload

---

# Startup Sequence (start.sh)

1. **Environment loading** — `load_env_bundle()` decodes base64 env bundles, normalizes vars
2. **DNS fix** — Applies DNS over HTTPS resolution for blocked environments
3. **Validate secrets** — Requires `LLM_API_KEY`, `LLM_MODEL`, `GATEWAY_TOKEN`
4. **LLM provider mapping** — Extracts provider prefix from `LLM_MODEL`, sets the corresponding `{PROVIDER}_API_KEY` env var
5. **Key pool promotion** — `promote_first_pool_key()` mirrors first key from `{PROVIDER}_API_KEYS` pool to singular env var
6. **Workspace restore** — Runs `openclaw-sync.py restore` from HF Dataset
7. **Config generation** — Builds `openclaw.json` via jq with gateway token, model, logging, channels, plugins, trusted proxies, CORS origins
8. **Plugin re-install** — Reads `.plugins.installs` from saved config, re-installs via `openclaw plugins install`
9. **Optional Proton VPN** — Starts `protonvpn-manager.sh service` if enabled
10. **Startup commands** — Runs `HUGGINGCLAW_RUN`, `HUGGINGCLAW_STARTUP_*`, and `workspace/startup.sh` scripts
11. **Background services** — Starts health-server, OpenClaw gateway, workspace sync loop, WhatsApp guardian, JupyterLab, devdata sync
12. **Gateway loop** — `while true` loop restarts OpenClaw gateway on crash (with optional restart limit)

---

# Key Configuration / Environment Variables

The primary entrypoint for configuration is HF Spaces **Secrets** and **Variables**:

| Variable | Required | Purpose |
|----------|----------|---------|
| `LLM_API_KEY` | Yes | Primary LLM API key (auto-mapped to provider-specific var) |
| `LLM_MODEL` | Yes | Model ID, e.g. `google/gemini-2.5-flash` |
| `GATEWAY_TOKEN` | Yes | Auth token for Control UI (+ JupyterLab) |
| `HF_TOKEN` | No | HF token for Dataset backup persistence |
| `TELEGRAM_BOT_TOKEN` | No | Telegram bot integration |
| `WHATSAPP_ENABLED` | No | WhatsApp channel (`true`/`false`) |
| `CLOUDFLARE_WORKERS_TOKEN` | No | Auto-provision Cloudflare Worker proxy |
| `SOCKS5_PROXY_URL` | No | External SOCKS5 proxy (e.g. Render Tor proxy) |
| `HUGGINGCLAW_RUN` | No | Arbitrary bash commands run on boot |
| `PROTONVPN_ENABLED` | No | Enable WireGuard VPN tunnel (`true`/`false`) |
| `PROTONVPN_ROTATE_INTERVAL` | No | VPN IP rotation interval in minutes (default: 30) |

Per-provider API keys: `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GEMINI_API_KEY`, `DEEPSEEK_API_KEY`, `OPENROUTER_API_KEY`, etc. Key pools via `{PROVIDER}_API_KEYS` (comma-separated).

Full reference in `.env.example`.

---

# Development Commands

```bash
# Local build & run with Docker
docker build --build-arg OPENCLAW_VERSION=latest -t huggingclaw .
docker run -p 7861:7861 --env-file .env huggingclaw

# Without Docker (requires openclaw CLI globally)
npm install -g openclaw@latest
export $(cat .env | xargs)
bash start.sh

# Render YouTube transcript proxy
cd render-youtube-proxy/
docker build -t render-yt-proxy .
docker run -p 8000:8000 -e PROXY_AUTH_TOKEN=... render-yt-proxy

# Vercel YouTube transcript proxy
cd vercel-youtube-proxy/
vercel deploy --prod

# MCP YouTube transcript server (standalone)
cd mcp-servers/youtube-transcript/
node server.js
```

**No test suite, no linter, no build step for the main repo.** Validate changes by building the Docker image and testing locally.

---

# Common Tasks

- **Deploying new HF Space version** — Push to the linked HF Space git remote; Docker build runs automatically
- **Changing the OpenClaw version** — Set `OPENCLAWS_VERSION` as an HF Space **Variable** (not secret) and trigger a rebuild
- **Adding a new LLM provider** — Edit the `case` block in `start.sh` (~line 189-238) mapping provider prefixes to env vars; update `.env.example` docs and `multi-provider-key-rotator.cjs` provider list
- **Adding a new channel proxy** — Create a new `{channel}-proxy.cjs` file, add it to the `NODE_OPTIONS` chain in the Dockerfile, and register its routing in `cloudflare-proxy.js`
- **Adding a new WireGuard peer** — Edit the `WG_PEERS` array in `protonvpn-manager.sh` (format: `privateKey|peerPublicKey|endpoint`)
- **Troubleshooting startup** — Check HF Space logs for `[hc-proxy]`, `[hc-sync]`, `[hc-vpn]`, `ERROR:` prefixed lines; inspect `/tmp/sync-status.json`, `/tmp/huggingclaw-wa-status.json`, `/home/node/.protonvpn/status` for runtime state
- **Debugging proxy issues** — `cloudflare-proxy.js` logs to stderr with `[hc-proxy]` prefix; channel proxy files use `[telegram-proxy]`, `[whatsapp-proxy]` prefixes

---

# Important Caveats

- **No root package.json** — The repo is a deployment config bundle, not a conventional Node.js/Python project. Scripts are standalone. All Node.js deps come from the OpenClaw prebuilt image or `browser-deps/`.
- **No tests** — No test infrastructure. Validate by building the Docker image and running locally.
- **`telegram-worker-proxy/` is gitignored** at the top level but present as a nested git repo. Separate deployable artifact.
- **`vercel-youtube-proxy/` is gitignored** — unused subproject kept as reference.
- **HF Spaces restrictions** — Outbound connections to Telegram and WhatsApp domains are blocked by HF firewall. The proxy layers (`cloudflare-proxy.js`, `proxy-pool.py`, channel-specific preloads) exist to work around this. `NODE_OPTIONS` preloads patch all major Node.js networking APIs.
- **No Tor in main container** — Tor usage caused HF account locks. SOCKS5 proxy is external (via `SOCKS5_PROXY_URL`).
- **WireGuard uses wireproxy** — Userspace HTTP CONNECT proxy, no TUN/NET_ADMIN capabilities needed. Works on container platforms (HF Spaces, Render).
- **JupyterLab is optional** — Only installed when `DEV_MODE=true` (build-time) or `GATEWAY_TOKEN` is set (auto-enables at runtime). Set `DEV_MODE=false` explicitly to opt out.
- **Proxy-pool limitations** — Free SOCKS5 proxies are unreliable; the Cloudflare Worker proxy is the recommended path for Telegram.
- **Channel proxy preloads** — All channel proxy files are loaded as `--require` preloads regardless of whether the channel is enabled. They are no-ops when their env vars are unset. This is by design — they patch early, check config later.
- **NODE_OPTIONS chain** — The full preload chain is: `dns-fix.cjs → cloudflare-proxy.js → telegram-proxy.cjs → whatsapp-proxy.cjs`. Order matters — DNS fix must load first.
