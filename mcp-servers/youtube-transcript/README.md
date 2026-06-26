# MCP YouTube Transcript Proxy

Render proxy ke through YouTube transcripts fetch karne ke liye MCP server.

## Usage

### Codex CLI

`.codex/config.toml` mein add karo:

```toml
[mcp_servers.youtube-transcript]
command = "node"
args = ["<path-to>/mcp-servers/youtube-transcript/server.js"]
env = { YT_PROXY_TOKEN = "your-token" }
```

Ya npx se:

```toml
[mcp_servers.youtube-transcript]
command = "npx"
args = ["-y", "mcp-youtube-transcript-proxy"]
env = { YT_PROXY_TOKEN = "your-token" }
```

### Claude Desktop

`claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "youtube-transcript": {
      "command": "node",
      "args": ["/full/path/to/mcp-servers/youtube-transcript/server.js"],
      "env": {
        "YT_PROXY_TOKEN": "your-token"
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `get_transcript` | Transcript with timestamps |
| `get_transcript_text` | Plain text (no timestamps) |
| `list_transcripts` | Available languages for a video |

## Env Vars

| Variable | Default | Description |
|----------|---------|-------------|
| `YT_PROXY_BASE` | `https://render-youtube-proxy.onrender.com` | Render proxy URL |
| `YT_PROXY_TOKEN` | — | Auth token (required) |
