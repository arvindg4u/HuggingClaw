# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# HuggingClaw — Overview

HuggingClaw is a Docker-based deployment of an **OpenClaw** LLM gateway, bundled with a **JupyterLab terminal**, that runs on **HuggingFace Spaces** (free tier: 2 vCPU, 16GB RAM). It provides an always-on AI assistant accessible via Telegram, WhatsApp, and a Web Control UI, with automatic workspace backup to a private HF Dataset.

**Stack:** Docker, Node.js, Python 3, OpenClaw gateway (Node.js), JupyterLab

**Deployment target:** HuggingFace Spaces Docker runtime (port 7861 exposed)

---

# Architecture

## Entrypoint & Routing

The public endpoint is `health-server.js` (Node.js, port 7861) which acts as a **reverse proxy + dashboard**:

| Path | Backend | Internal Port |
|------|---------|--------------|
| `/` | HuggingClaw dashboard (health-server.js) | 7861 |
| `/app/` | OpenClaw Control UI | 7860 |
| `/terminal/` | JupyterLab terminal | 8888 |
| `/health` | Health check endpoint | 7861 |

## Core Files

### Entrypoint
- `Dockerfile` — Multi-stage build: pulls pre-built `ghcr.io/openclaw/openclaw` image, then adds Node.js 22-slim runtime, system deps, JupyterLab (optional), and copies all app files.
- `start.sh` (~1852 lines) — Main startup script. Orchestrates the entire boot sequence.

### Reverse Proxy / Dashboard
- `health-server.js` — Node.js HTTP server. Reverse-proxies `/app/` to OpenClaw on :7860, `/terminal/` to JupyterLab on :8888. Serves the dashboard at `/`. Handles auth, session cookies, CORS, and displays sync/uptime/status.

### Network / Proxy Layers
- `cloudflare-proxy.js` — Node.js `--require` preload that patches `http.request`, `https.request`, `fetch`, `net.connect`, `tls.connect` to route blocked domains (Telegram API, opencode.ai, WhatsApp) through a SOCKS5 proxy. Also handles Cloudflare Worker proxy fast-path for Telegram.
- `proxy-pool.py` — Self-rotating SOCKS5 proxy pool. Fetches free SOCKS5 proxies, tests against api.telegram.org, runs a local SOCKS5 server on :9050 with auto-rotation every 10 minutes.
- `render-tor-proxy/Dockerfile` — Standalone Tor + WebSocket proxy for Render (free tier). Pure asyncio, no websockets library. Handles WS upgrade + bidirectional TCP relay through Tor SOCKS5.
- `telegram-worker-proxy/` — Cloudflare Worker (wrangler) for proxying Telegram/WhatsApp API calls. Deployed via `wrangler deploy` from its subdirectory.

### Persistence / Backup
- `openclaw-sync.py` — Background sync loop (3 min default). Uploads/restores OpenClaw workspace data, app state, and WhatsApp credentials to/from a private HF Dataset (`huggingclaw-backup`). Uses `huggingface_hub`.
- `jupyter-devdata-sync.py` — Similar sync for JupyterLab root directory devdata to a separate HF Dataset (`huggingclaw-devdata`).

### Key Rotation
- `multi-provider-key-rotator.cjs` — Node.js `--require` preload. Intercepts OpenClaw HTTP requests to LLM providers, round-robins API keys from `{PROVIDER}_API_KEYS` env var pools. Handles 429/402 backoff, blacklisting, strikes.

### Channel Integrations
- `wa-guardian.js` — WhatsApp session guardian. Monitors OpenClaw gateway via WebSocket for WhatsApp "515 Restart" events, re-pairs credentials automatically.
- `cloudflare-proxy.js` also handles Telegram bot webhook proxying.

### SSH/iframe Fixes
- `iframe-fix.cjs` — Node.js preload that patches HTTP `Server.prototype.emit` to strip `X-Frame-Options` and fix CSP `frame-ancestors` for HF Spaces embedding.

### Environment Builder
- `env-builder.html` / `env-builder.js` — Client-side web UI for generating a base64-encoded `HUGGINGCLAW_ENV_BUNDLE` from a form. No server dependency.

---

# Startup Sequence (start.sh)

1. **Environment loading** — `load_env_bundle()` decodes base64 env bundles, normalizes vars
2. **Validate secrets** — Requires `LLM_API_KEY`, `LLM_MODEL`, `GATEWAY_TOKEN`
3. **LLM provider mapping** — Extracts provider prefix from `LLM_MODEL`, sets the corresponding `{PROVIDER}_API_KEY` env var
4. **Key pool promotion** — `promote_first_pool_key()` mirrors first key from `_{PROVIDER}_API_KEYS` pool to singular env var
5. **Workspace restore** — Runs `openclaw-sync.py restore` from HF Dataset
6. **Config generation** — Builds `openclaw.json` via jq with gateway token, model, logging, channels, plugins, trusted proxies, CORS origins
7. **Plugin re-install** — Reads `.plugins.installs` from saved config, re-installs via `openclaw plugins install`
8. **Startup commands** — Runs `HUGGINGCLAW_RUN`, `HUGGINGCLAW_STARTUP_*`, and `workspace/startup.sh` scripts
9. **Background services** — Starts health-server, OpenClaw gateway, workspace sync loop, WhatsApp guardian, JupyterLab, devdata sync
10. **Gateway loop** — `while true` loop restarts OpenClaw gateway on crash (with optional restart limit)

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

# Cloudflare Worker (subdirectory)
cd telegram-worker-proxy/
npx wrangler deploy    # Deploy worker
npx wrangler dev       # Local dev

# Render Tor proxy
cd render-tor-proxy/
docker build -t tor-ws-proxy .
docker run -p 10000:10000 tor-ws-proxy
```

**No test suite, no linter, no build step for the main repo.** The gitignore excludes `telegram-worker-proxy/` (kept as embedded sub-project reference). There is no root `package.json`.

# Common Tasks

- **Deploying new HF Space version** — Push to the linked HF Space git remote; Docker build runs automatically
- **Changing the OpenClaw version** — Set `OPENCLAW_VERSION` as an HF Space **Variable** (not secret) and trigger a rebuild
- **Adding a new LLM provider** — Edit the `case` block in `start.sh` (~line 189-238) mapping provider prefixes to env vars; update `.env.example` docs and `multi-provider-key-rotator.cjs` provider list
- **Troubleshooting startup** — Check HF Space logs for `[hc-proxy]`, `[sync]`, `ERROR:` prefixed lines; inspect `/tmp/sync-status.json` and `/tmp/huggingclaw-wa-status.json` for runtime state
- **Debugging proxy issues** — `cloudflare-proxy.js` logs to stderr with `[hc-proxy]` prefix; `SOCKS5_PROXY_URL` and `SOCKS5_PROXY_DOMAINS` control routing behavior

# Important Caveats

- **No root package.json** — The repo is a deployment config bundle, not a conventional Node.js/Python project. Scripts are standalone.
- **No tests** — There is no test infrastructure. Changes should be validated by building the Docker image and running locally.
- **`telegram-worker-proxy/` is gitignored** at the top level but present as a nested git repo. It's a separate deployable artifact.
- **HF Spaces restrictions** — Outbound connections to Telegram/Discord/WhatsApp domains are blocked by HF firewall. The proxy layers (`cloudflare-proxy.js`, `proxy-pool.py`, `render-tor-proxy/`) exist specifically to work around this.
- **No Tor in main container** — Tor usage caused HF account locks. SOCKS5 proxy is external (via `SOCKS5_PROXY_URL` pointing to Render/deployed Tor proxy).
- **JupyterLab is optional** — Only installed when `DEV_MODE=true` (build-time) or `GATEWAY_TOKEN` is set (auto-enables at runtime). Set `DEV_MODE=false` explicitly to opt out.
- **Proxy-pool limitations** — Free SOCKS5 proxies are unreliable; the Cloudflare Worker proxy is the recommended path for Telegram.
