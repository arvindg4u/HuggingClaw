# ── HuggingClaw Tor Proxy for Render (Free Tier) ──
# Routes traffic through Tor SOCKS5 for IP rotation
# Purpose: avoid IP-based rate limiting on opencode.ai
# Base: ~45MB (Alpine 5MB + Tor 15MB + Node.js 25MB)
FROM alpine:3.19

RUN apk add --no-cache tor nodejs

# Tor config — ClientOnly means no relay/exit (privacy-safe)
# Use /app/tor-data so path survives Docker layers
RUN mkdir -p /app/tor-data && chmod 700 /app/tor-data
RUN printf '%s\n' \
  'SOCKSPort 127.0.0.1:9150' \
  'DataDirectory /app/tor-data' \
  'Log notice stdout' \
  'ClientOnly 1' \
  'ExitRelay 0' \
  'BridgeRelay 0' \
  > /app/torrc

WORKDIR /app
COPY package.json index.js ./

EXPOSE 10000

CMD ["node", "index.js"]
