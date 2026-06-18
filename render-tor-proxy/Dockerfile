# ── Tor SOCKS5 Proxy for Render (Free Tier) ──
# Deploy on Render, then HF Space connects here for IP rotation.
# Tor runs OUTSIDE HF Spaces = no ToS violation.
FROM alpine:3.19

RUN apk add --no-cache tor socat

# Health check script + Tor runner
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/sh
# Minimal torrc
cat > /tmp/torrc << 'TOREOC'
SOCKSPort 0.0.0.0:9050
DataDirectory /tmp/tor-data
Log notice stdout
ClientOnly 1
ExitRelay 0
BridgeRelay 0
TOREOC

mkdir -p /tmp/tor-data
chmod 700 /tmp/tor-data

# Start Tor in background
tor -f /tmp/torrc &
TOR_PID=$!

# Health check server on Render's PORT (required for web service)
# Responds with HTTP 200 to any request
PORT=${PORT:-10000}
echo "Starting health check on port $PORT"
socat TCP-LISTEN:$PORT,fork,reuseaddr SYSTEM:'echo -e "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"' &

# Wait for Tor
sleep 3
echo "Tor SOCKS5 ready on 0.0.0.0:9050"

# Keep running
wait $TOR_PID
EOF

RUN chmod +x /entrypoint.sh

EXPOSE 9050

CMD ["/entrypoint.sh"]
