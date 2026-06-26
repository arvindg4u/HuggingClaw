# YouTube Transcript MCP Server

Local yt-dlp + Vercel fallback for YouTube transcripts. No proxies, no tunnels.

## Sources (in order)

1. **yt-dlp** (local) — tries android → tv → ios → web clients
2. **Vercel API** (remote) — calls `YT_API_BASE` if yt-dlp fails

## Setup

```bash
pip install yt-dlp
```

### Codex CLI

```toml
[mcp_servers.youtube-transcript]
command = "node"
args = ["<repo>/mcp-servers/youtube-transcript/server.js"]
env = { YT_API_BASE = "https://yt-transcript-proxy.vercel.app", YT_API_TOKEN = "your-token" }
```

## Tools

- `get_transcript` — Transcript text
- `get_transcript_text` — Plain text
- `get_video_info` — Video metadata + available languages
