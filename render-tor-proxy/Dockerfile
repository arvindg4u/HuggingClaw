# ── Tor SOCKS5 Proxy for Render (Free Tier) ──
# Deploy on Render, then HF Space connects here for IP rotation.
# Tor runs OUTSIDE HF Spaces = no ToS violation.
FROM alpine:3.19

RUN apk add --no-cache tor

# Health check server (tiny HTTP server using nc + printf)
RUN cat > /health.sh << 'HEOF'
#!/bin/sh
PORT=${PORT:-10000}
while true; do
  nc -l -p "$PORT" -e /bin/sh -c 'printf "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"' 2>/dev/null
done
HEOF

RUN chmod +x /health.sh

# Tor startup script
RUN cat > /entrypoint.sh << 'EOF'
#!/bin/sh

# Write torrc
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

# Start health check server in background (for Render's health checks)
/health.sh &
HEALTH_PID=$!

# Wait for Tor to bootstrap
echo "Waiting for Tor to bootstrap..."
sleep 5

# Keep running
echo "Tor SOCKS5 ready on 0.0.0.0:9050"
echo "Health check on PORT=$PORT"
wait $TOR_PID
EOF

RUN chmod +x /entrypoint.sh

EXPOSE 9050

CMD ["/entrypoint.sh"]
