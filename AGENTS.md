# Repository Guidelines

## Project Structure & Module Organization

HuggingClaw is a Docker-based deployment bundle for running an OpenClaw LLM gateway with JupyterLab on HuggingFace Spaces. The repo has no root `package.json` — all scripts are standalone.

**Root scripts** — `start.sh` (entrypoint), `health-server.js` (reverse proxy/dashboard), `cloudflare-proxy.js` (SOCKS5 routing), `proxy-pool.py` (SOCKS5 proxy pool), `openclaw-sync.py` (HF Dataset backup), `multi-provider-key-rotator.cjs` (LLM key rotation), `wa-guardian.js` (WhatsApp session guardian).

**Subprojects** — `telegram-worker-proxy/` (Cloudflare Worker), `render-relay/` (WebSocket-to-TCP relay), `tor-proxy/` (Tor + WebSocket proxy), `vercel-proxy/` (Vercel serverless function).

**Configuration** — `.env.example` documents all supported environment variables. Secrets are loaded at runtime only.

## Build, Test, and Development Commands

```bash
# Local build and run
docker build --build-arg OPENCLAW_VERSION=latest -t huggingclaw .
docker run -p 7861:7861 --env-file .env huggingclaw

# Deploy Cloudflare Worker (subdirectory)
cd telegram-worker-proxy/ && npx wrangler deploy

# Build and run Tor proxy (subdirectory)
cd tor-proxy/ && docker build -t tor-ws-proxy . && docker run -p 10000:10000 tor-ws-proxy
```

There is **no test suite or linter**. Validate changes by building the Docker image and testing both `/app/` (OpenClaw UI) and `/terminal/` (JupyterLab) with a valid LLM provider.

## Coding Style & Naming Conventions

- **Shell** (`start.sh`): Use `set -e`, quote all variables, comment non-obvious logic
- **Node.js**: Plain CommonJS (`.js`, `.cjs`). No TypeScript. Use descriptive identifiers
- **Python**: PEP 8 conventions. Standalone scripts, no virtualenv or package manager
- **Files**: kebab-case (`cloudflare-proxy.js`, `proxy-pool.py`)
- **Log tags**: Prefix runtime logs with `[hc-*]` (e.g., `[hc-proxy]`, `[hc-sync]`)

## Commit & Pull Request Guidelines

Commits follow **Conventional Commits** with lowercase scope prefixes:

```
feat: Tor SOCKS5 proxy for IP rotation on Render free tier
fix: Tor torrc path — use /app/ not /tmp/ (Docker layer issue)
chore: add WS data event logging to debug CLOSE on Render
```

PRs should describe the change, reference any related issues, and note which channels (Telegram, WhatsApp, Web UI) and deployment targets (HF Spaces, Render, Cloudflare Worker) were tested.

## Security & Configuration Tips

- Never hardcode secrets — use environment variables loaded at runtime
- HF Spaces scans Docker layers for Tor binaries — use external `SOCKS5_PROXY_URL` instead of bundling Tor
- Outbound connections to Telegram and WhatsApp are blocked by HF Spaces — the proxy layers (`cloudflare-proxy.js`, `proxy-pool.py`) exist to work around this
- Generate `GATEWAY_TOKEN` with `openssl rand -hex 32`
- Prefer the Cloudflare Worker proxy over the free SOCKS5 proxy pool for reliability in production
