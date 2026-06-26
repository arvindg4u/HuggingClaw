# Vercel YouTube Transcript Proxy

**Zero local setup.** Deploy to Vercel, use as remote MCP server.

## Deploy

```bash
cd vercel-youtube-proxy
vercel deploy --prod
```

Or connect Git repo to Vercel — set Root Directory to `vercel-youtube-proxy`.

## Remote MCP Config

```json
{
  "mcpServers": {
    "youtube-transcript": {
      "url": "https://vercel-youtube-proxy-chi.vercel.app/mcp"
    }
  }
}
```

No auth needed unless you set `PROXY_AUTH_TOKEN`.

## If YouTube blocks Vercel IP (future)

1. Create free account at [webshare.io](https://www.webshare.io) → 10 free residential proxies
2. On Vercel dashboard → add env vars:
   - `WEBSHARE_USERNAME` = your webshare username
   - `WEBSHARE_PASSWORD` = your webshare password
3. App auto-detects and uses Webshare residential proxies

## REST API (without MCP)

```
GET https://vercel-youtube-proxy-chi.vercel.app/transcript/VIDEO_ID/text?lang=en
```
