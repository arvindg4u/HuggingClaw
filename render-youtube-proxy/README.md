# Render YouTube Transcript Proxy

YouTube transcripts ke liye REST API proxy — HF Spaces se YouTube block hai, Render free tier pe deploy karo, Render ke IP se fetch karega.

## Deploy on Render

1. **Is directory ko** GitHub repo mein push karo
2. [Render Dashboard](https://dashboard.render.com) mein **New + → Web Service**
3. Connect repo, set:
   - **Name**: `yt-transcript-proxy` (ya kuch bhi)
   - **Root Directory**: `render-youtube-proxy`
   - **Environment**: `Docker`
   - **Plan**: Free
4. **Environment Variables**:
   - `PROXY_AUTH_TOKEN` → `openssl rand -hex 32` se generate karo
5. Deploy karo — Render Docker build karega aur run karega

**Self-ping**: App khud ko har 10 min mein `/health` hit karta rahega — Render sleep nahi karega. Koi external cron zaroorat nahi. ✅

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

## Usage from HuggingClaw

### Via MCP (recommended)

MCP server already create hai `mcp-servers/youtube-transcript/` mein. Codex/Claude ko do tools mil jayenge:

- `get_transcript` — timestamped transcript
- `get_transcript_text` — plain text
- `list_transcripts` — available languages

### Via raw fetch

```
fetch(url="https://render-youtube-proxy.onrender.com/transcript/VIDEO_ID",
      headers={"X-Proxy-Token": "your-token"})
```
