# Render YouTube Transcript Proxy

Uses **yt-dlp** directly — no proxies, no tunnels, no TOS violations.

## Deploy on Render

1. Push this dir to GitHub
2. Render → **New + → Web Service** → Docker environment
   - **Root Directory**: `render-youtube-proxy`
   - **Plan**: Free
3. Env: `PROXY_AUTH_TOKEN` = your token
4. Deploy

## Why yt-dlp?

- `youtube-transcript-api` library → ❌ IP blocked
- Proxy rotation → ❌ Violates HF Spaces TOS
- **yt-dlp** with `player_client=android` → ✅ Works

Tries multiple YouTube clients in order: **android → tv → ios → web → mweb**

## Endpoints

| GET | Path | Description |
|-----|------|-------------|
| `/health` | Health check |
| `/transcript/{video_id}` | Transcript (JSON) |
| `/transcript/{video_id}/text` | Plain text |
| `/transcripts/{video_id}` | Available languages |

**Auth**: `X-Proxy-Token: <token>` header
