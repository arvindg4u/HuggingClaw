# Render YouTube Proxy — with PO Token bypass

Deploy on Render free tier. Uses:

- **yt-dlp** — fetches transcripts via multiple player clients
- **bgutil-ytdlp-pot-provider** (sidecar) — generates Proof-of-Origin (PO) tokens to bypass YouTube IP blocks
- **FastAPI** — REST API for transcript retrieval

## Why PO Tokens?

YouTube blocks all major cloud provider IP ranges (Render, HF Spaces, Vercel, AWS, GCP).
PO Tokens prove your client is legitimate (Botguard attestation), bypassing IP-based blocking.

## Deploy on Render

1. Fork/clone this repo
2. Create a **Web Service** on Render
3. Set:
   - **Root Directory**: `render-youtube-proxy`
   - **Runtime**: Docker
   - **Port**: 8000
4. Add environment variable:
   - `PROXY_AUTH_TOKEN` — set a secure token
5. Deploy

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
