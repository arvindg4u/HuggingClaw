# Repository Guidelines

## Project Structure & Module Organization

HuggingClaw is a Docker-based deployment of OpenClaw LLM gateway + JupyterLab for HuggingFace Spaces. Scripts are standalone — no root `package.json`.

| Path | Purpose |
|------|---------|
| `start.sh` / `Dockerfile` | Entrypoint and multi-stage build |
| `health-server.js` | Reverse proxy / dashboard (port 7861) |
| `cloudflare-proxy.js` | Node.js preload — routes blocked domains through SOCKS5 |
| `proxy-pool.py` | Self-rotating SOCKS5 proxy pool |
| `openclaw-sync.py` | Background workspace backup to HF Dataset |
| `jupyter-devdata-sync.py` | JupyterLab devdata backup |
| `multi-provider-key-rotator.cjs` | Round-robins LLM API keys on 429/402 backoff |
| `telegram-worker-proxy/` | Cloudflare Worker for Telegram/WhatsApp API |
| `render-relay/` / `tor-proxy/` | WebSocket/Tor proxies for Render free tier |
| `.env.example` | Full environment variable reference |

## Build, Test, and Development Commands

```bash
# Local build & run
docker build --build-arg OPENCLAW_VERSION=latest -t huggingclaw .
docker run -p 7861:7861 --env-file .env huggingclaw

# Cloudflare Worker (subdirectory)
cd telegram-worker-proxy/ && npx wrangler deploy

# Render Tor proxy
cd tor-proxy/ && docker build -t tor-ws-proxy . && docker run -p 10000:10000 tor-ws-proxy
```

No test suite or linter exists. Validate changes by building the Docker image and testing both `/app/` (OpenClaw UI) and `/terminal/` (JupyterLab) with a valid LLM provider.

## Coding Style & Naming Conventions

- **Shell scripts**: `set -e`, quote all variables, comment non-obvious logic
- **Node.js**: Plain CommonJS (`.js`/`.cjs`). No TypeScript. Descriptive names over brevity
- **Python**: PEP 8 conventions. Standalone scripts, no virtualenv
- **Files**: kebab-case (`cloudflare-proxy.js`, `proxy-pool.py`)
- **Log tags**: Prefix with `[hc-*]` (e.g., `[hc-proxy]`, `[hc-sync]`)

## Commit & Pull Request Guidelines

Use **Conventional Commits** with lowercase scope prefixes:

```
feat: add wireproxy for userspace WireGuard → SOCKS5
fix: replace dead meek-azure with Snowflake (WebRTC)
clean: remove all proxy/VPN/WireGuard code
```

PRs should describe the change, reference related issues, and note which channels (Telegram, WhatsApp, Web UI) and deployment targets (HF Spaces, Render, Cloudflare Worker) were tested.

## Security & Configuration Tips

- Never hardcode secrets — use environment variables loaded at runtime
- HF Spaces scans Docker layers for Tor — use external `SOCKS5_PROXY_URL` instead
- Outbound connections to Telegram/WhatsApp are blocked by HF Spaces — proxy layers exist to work around this
- Generate `GATEWAY_TOKEN` with `openssl rand -hex 32`
- Prefer the Cloudflare Worker proxy over the free SOCKS5 proxy pool for reliability
