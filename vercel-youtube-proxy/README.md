# Vercel YouTube Transcript Proxy

Zero local setup. Deploy to Vercel, use as remote MCP server.

## Deploy

```bash
cd vercel-youtube-proxy
vercel deploy --prod
```

Ya connect Git repo to Vercel — set Root Directory to `vercel-youtube-proxy`.

## Remote MCP Config

### Claude Desktop / Cursor / Cline

```json
{
  "mcpServers": {
    "youtube-transcript": {
      "url": "https://vercel-youtube-proxy-chi.vercel.app/mcp",
      "headers": {
        "X-Proxy-Token": "your-token"
      }
    }
  }
}
```

### Codex CLI

```toml
[mcp_servers.youtube-transcript]
url = "https://vercel-youtube-proxy-chi.vercel.app/mcp"
headers = { X-Proxy-Token = "your-token" }
```

### Without MCP (direct REST)

```
GET https://vercel-youtube-proxy-chi.vercel.app/transcript/VIDEO_ID/text?lang=en
Header: X-Proxy-Token: your-token
```

## Why Vercel?

- Render IPs → YouTube blocked ❌
- Vercel IPs → YouTube not blocked ✅
- Free tier, auto-scales, no local setup
- No proxies, no TOS violations
