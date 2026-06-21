# ── HuggingClaw Tor Proxy for Render (Free Tier) ──
# Routes traffic through Tor SOCKS5 for IP rotation
# Purpose: avoid IP-based rate limiting on opencode.ai
# Base: ~45MB (Alpine 5MB + Tor 15MB + Node.js 25MB)
FROM alpine:3.19

RUN apk add --no-cache tor nodejs

# Tor config — ClientOnly means no relay/exit (privacy-safe)
RUN mkdir -p /tmp/tor-data && chmod 700 /tmp/tor-data
RUN echo 'SOCKSPort 127.0.0.1:9150\nDataDirectory /tmp/tor-data\nLog notice stdout\nClientOnly 1\nExitRelay 0\nBridgeRelay 0' > /tmp/torrc

WORKDIR /app
COPY package.json index.js ./

EXPOSE 10000

CMD ["node", "index.js"]
