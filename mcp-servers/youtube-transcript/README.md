# YouTube Transcript MCP Server

Uses **yt-dlp** directly to fetch YouTube transcripts — no proxies, no external APIs.

## How it works

1. Calls `yt-transcript.py` (Python MCP server) in the repo root
2. yt-dlp fetches transcripts using `player_client=android` (bypasses IP blocks)
3. Falls back through tv → ios → web clients

## Usage in Codex CLI

```toml
# .codex/config.toml
[mcp_servers.youtube-transcript]
command = "node"
args = ["<repo>/mcp-servers/youtube-transcript/server.js"]
```

## Tools

| Tool | Description |
|------|-------------|
| `get_transcript` | Transcript text from YouTube video |
| `get_transcript_text` | Same — plain text output |
| `get_video_info` | Video metadata + available transcript languages |

## Requirements

- Python 3.9+ with `yt-dlp` installed: `pip install yt-dlp`
- Node.js 18+ (for the MCP wrapper)

## No Render dependency

This MCP server calls `yt-transcript.py` directly — no Render proxy needed.
