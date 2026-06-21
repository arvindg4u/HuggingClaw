# ── HuggingClaw WireGuard (Proton VPN) Proxy for Render ──
# SOCKS5 + HTTP health check on same port
FROM samuelmoraesf/protonvpn-proxy:latest AS base

FROM alpine:3.19
RUN apk add --no-cache nodejs bash

# Copy wireproxy binary from base image (see Dockerfile: it's /usr/local/bin/)
COPY --from=base /usr/local/bin/wireproxy /usr/local/bin/wireproxy

# Copy entrypoint script to generate wireproxy config
COPY --from=base /entrypoint.sh /entrypoint.sh

# WireGuard config via env vars (same as base image)
ENV WG_PRIVATE_KEY=wHTOhHm7orE8evqF39HezxB8Vc+fwuVsEtDN2rl2HnA=
ENV WG_PEER_PUBLIC_KEY=Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=
ENV WG_ENDPOINT=146.70.202.34:51820

COPY run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 10000

CMD ["/run.sh"]
