# Vercel YouTube Transcript Proxy

YouTube transcripts via Vercel serverless functions. Lightweight, no temp files, no subprocess.

## Deploy on Vercel

```bash
cd vercel-youtube-proxy
vercel deploy --prod
```

Or connect Git repo to Vercel:
- **Root Directory**: `vercel-youtube-proxy`
- **Framework**: Other
- **Build**: `pip install -r requirements.txt`

### Env vars
- `PROXY_AUTH_TOKEN` — optional auth token

## Endpoints

| GET | Description |
|-----|-------------|
| `/health` | Health check |
| `/transcript/{video_id}?lang=en` | Transcript with segments |
| `/transcript/{video_id}/text?lang=en` | Plain text |
| `/transcripts/{video_id}` | Available languages |

Auth: `X-Proxy-Token: <token>` header

## Why Vercel?

- Render IPs → YouTube blocked ❌
- Vercel IPs → YouTube not blocked yet ✅
- Serverless, auto-scales, free tier
- No proxies, no TOS violations
