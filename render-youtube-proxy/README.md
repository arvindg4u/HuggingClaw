# Render YouTube Proxy — with PO Tokens + WireGuard VPN

Deploy on Render free tier. Uses:

- **yt-dlp** — fetches transcripts via multiple player clients
- **bgutil-ytdlp-pot-provider** (sidecar) — generates Proof-of-Origin (PO) tokens to bypass YouTube IP blocks
- **WireGuard VPN tunnel** (wireproxy) — routes traffic through residential IPs when PO tokens aren't enough

## Why Two Layers?

YouTube blocks all major cloud provider IP ranges (Render, HF Spaces, Vercel, AWS, GCP).

1. **PO Tokens** — Prove your client is legitimate via Botguard attestation. Bypasses most IP blocks.
2. **WireGuard VPN** — When PO tokens are still blocked (YouTube escalates), the VPN tunnel routes traffic through a residential IP. Uses [wireproxy](https://github.com/octeep/wireproxy) — userspace, no TUN/NET_ADMIN needed.

## Deploy on Render

1. Fork/clone this repo
2. Create a **Web Service** on Render
3. Set:
   - **Root Directory**: `render-youtube-proxy`
   - **Runtime**: Docker
   - **Port**: 8000
4. Add environment variable:
   - `PROXY_AUTH_TOKEN` — set a secure token (required)
5. **Optional — WireGuard VPN** (for when PO tokens aren't enough):
   - `WG_PRIVATE_KEY` — your WireGuard private key
   - `WG_PEER_PUBLIC_KEY` — peer public key
   - `WG_ENDPOINT` — endpoint `ip:port`
   - Or `WG_CONFIGS` — JSON array for multi-config rotation:
     ```json
     [{"privateKey":"...","peerPublicKey":"...","endpoint":"ip1:51820"},
      {"privateKey":"...","peerPublicKey":"...","endpoint":"ip2:51820"}]
     ```
   - `WG_ROTATE_INTERVAL` — rotation interval in minutes (default: 30)
6. Deploy

## API Usage

```bash
# Get plain-text transcript
curl -H "X-Proxy-Token: your-token" \
  "https://your-app.onrender.com/transcript/dQw4w9WgXcQ/text?lang=en"

# Get transcript with segments
curl -H "X-Proxy-Token: your-token" \
  "https://your-app.onrender.com/transcript/dQw4w9WgXcQ?lang=en"

# List available transcript languages
curl -H "X-Proxy-Token: your-token" \
  "https://your-app.onrender.com/transcripts/dQw4w9WgXcQ"

# Health check (no auth needed)
curl "https://your-app.onrender.com/health"

# Tunnel status
curl "https://your-app.onrender.com/tunnel"
```

## MCP Config

```json
{
  "mcpServers": {
    "youtube-transcript": {
      "url": "https://your-app.onrender.com/mcp",
      "headers": {
        "X-Proxy-Token": "your-token"
      }
    }
  }
}
```

## How the WireGuard Tunnel Works

The tunnel uses [wireproxy](https://github.com/octeep/wireproxy), a userspace WireGuard client that exposes an HTTP CONNECT proxy on `127.0.0.1:25345`.

- **No TUN/NET_ADMIN required** — works on Render's container platform
- **Auto-downloads** wireproxy binary on first start
- **Health checking** — pings `icanhazip.com` through the tunnel every 30s
- **Auto-rotation** — rotates to next config after 2 consecutive failures
- **Status file** at `/tmp/wireguard/status` — `connected` when tunnel is active

The app tries direct PO-token requests first (fast path). If all player clients are blocked, it retries through the WireGuard tunnel. The response `client` field shows `tunnel-*` when served via the VPN.
