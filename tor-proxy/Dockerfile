# ── HuggingClaw Tor Proxy for Render (Free Tier) ──
# Routes traffic through Tor SOCKS5 for IP rotation
# Purpose: avoid IP-based rate limiting on opencode.ai
# ~60MB (Node.js 40MB + Tor 15MB + ws lib 5MB)
FROM node:22-alpine

RUN apk add --no-cache tor

# Tor config — ClientOnly means no relay/exit (privacy-safe)
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
COPY package.json package-lock.json ./
RUN npm install --omit=dev
COPY index.js ./

EXPOSE 10000

CMD ["node", "index.js"]
