# ── HuggingClaw WireGuard (Proton VPN) Proxy for Render ──
# IP rotation: set WG_ENDPOINTS with comma-separated endpoint IP:port pairs
#   WG_ENDPOINTS=ip1:51820,ip2:51820,ip3:51820
#   WG_ROTATION_INTERVAL=1800000  (ms, default 30 min)
# Falls back to WG_ENDPOINT for single-endpoint mode.
FROM node:22-alpine

RUN apk add --no-cache wget ca-certificates

# Download wireproxy binary (userspace, no kernel needed)
ARG TARGETARCH=amd64
ARG WIREPROXY_VERSION=1.1.2
RUN wget -qO- "https://github.com/pufferffish/wireproxy/releases/download/v${WIREPROXY_VERSION}/wireproxy_linux_${TARGETARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin wireproxy

ENV WG_PRIVATE_KEY=wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=
ENV WG_PEER_PUBLIC_KEY=Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=
ENV WG_ENDPOINT=146.70.202.34:51820

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm install --omit=dev
COPY relay.js .

EXPOSE 10000

CMD ["node", "relay.js"]
