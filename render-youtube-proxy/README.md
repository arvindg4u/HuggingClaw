# Render YouTube Transcript Proxy

YouTube transcripts ke liye REST API proxy — HF Spaces se YouTube block hai, Render free tier pe deploy karo, Render ke IP se fetch karega.

## Deploy on Render

1. **Is directory ko** apne GitHub repo mein push karo
2. [Render Dashboard](https://dashboard.render.com) mein **New + → Web Service**
3. Connect repo, set:
   - **Name**: `yt-transcript-proxy` (ya kuch bhi)
   - **Root Directory**: `render-youtube-proxy`
   - **Environment**: `Docker`
   - **Plan**: Free
4. **Environment Variables**:
   - `PROXY_AUTH_TOKEN` → `openssl rand -hex 32` se generate karo
5. Deploy karo — Render Docker build karega aur run karega

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/transcript/{video_id}` | Transcript with timestamps |
| GET | `/transcript/{video_id}/text` | Plain text transcript |
| GET | `/transcripts/{video_id}` | List available languages |

**Auth**: Har request mein `X-Proxy-Token: <your-token>` header bhejo.

## Test

```bash
curl -H "X-Proxy-Token: your-token" \
  https://yt-transcript-proxy.onrender.com/health

curl -H "X-Proxy-Token: your-token" \
  https://yt-transcript-proxy.onrender.com/transcript/dQw4w9WgXcQ

curl -H "X-Proxy-Token: your-token" \
  https://yt-transcript-proxy.onrender.com/transcript/dQw4w9WgXcQ/text
```

## Keep Alive

Render free tier 15 min inactivity ke baad sleep karta hai. Cron ping set karo:

```bash
curl -s https://yt-transcript-proxy.onrender.com/health
```

[UptimeRobot](https://uptimerobot.com) (free) ya [cron-job.org](https://cron-job.org) (free) use karo har 10 min mein `/health` hit karne ke liye.

## Usage from HuggingClaw

Is API ko call karne ke liye do options hain:

### Option A: Via LLM fetch tool
Seedha REST API call karo tool se:
```
fetch(url="https://yt-transcript-proxy.onrender.com/transcript/VIDEO_ID", headers={"X-Proxy-Token": "your-token"})
```

### Option B: Custom MCP server wrapper
Ek chhota MCP server banao jo is API ko wrap kare — tab LLM seedha tool call kar sakta hai directly Claude/Codex mein.
