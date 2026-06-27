#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 🛡️  Proton VPN Manager — WireGuard tunnel via wireproxy.
#     Userspace — no TUN/NET_ADMIN needed. Works on HF Spaces.
#
#     17 built-in Proton VPN FREE WireGuard configs.
#     Uses HTTP CONNECT (standard HTTPS tunnel, not SOCKS5).
# ════════════════════════════════════════════════════════════════

set -euo pipefail

log()  { echo "[hc-vpn] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
err()  { echo "[hc-vpn] ERROR: $*" >&2; }
warn() { echo "[hc-vpn] WARNING: $*" >&2; }

ROTATE="${PROTONVPN_ROTATE_INTERVAL:-30}"
TUNNEL_PORT=25345
STATE_DIR="/home/node/.protonvpn"
STATUS_FILE="${STATE_DIR}/status"
WIREPROXY="/usr/local/bin/wireproxy"
WIREPROXY_TMP="/tmp/wireproxy"

# ── 17 built-in Proton VPN FREE WireGuard configs ──
declare -a WG_PEERS=(
  "SH3bUChOJ4P7h93xjW8bz/CqeKrdl/9Z4J1EXwH4RUE=|Uqp1/VJ/Lz2VoN/2D0HEG7G8WDxLJm7+JNC5KZrUREw=|149.88.30.88:51820"
  "oDs/VVhAgFelbHPBGDFo+SiJC1MeVlhftJWXNRj9rGY=|oGVahl/rkt0i22DILrVpPSmYZmqcmSup/HQ/upVf2Vg=|138.199.35.120:51820"
  "gKWzO+GHInsyQTPghaxXp9xLM4knQqyuCLOzvKlXoGM=|Y4jxn/IIoorfo/X99RZFU6HbL9WWn7ffGI5isYFU9lo=|146.70.202.34:51820"
  "iCemcNphbxPmP+7WK3/oqUruKYlI0BksqwdbYX7VsFQ=|8il/lBt/NRXyh309nNf6Ebcu8mtOIuI9QCZe1MAozSc=|146.70.147.98:51820"
  "AKjCQtjE7DY6L14TPy4FkuznmXajWHHKsXgoYpGiJ0o=|+tBxOtFy6U050wKXUHW16Ya8gzRVoAGdSZGQ2PokrGA=|149.22.84.149:51820"
  "KCRBFg3o8AZ2d8hQy3Ptsc/KVby2d4EimjHVzNH8VFM=|wP/7Xi9sTiO1XMpLXf/OUJiJc1E0PA3KyskMtGajEFA=|146.70.202.2:51820"
  "4DwU54de/J71xWRReiOI27V+fJutYlPqIUiWL5/DIlU=|W0ke+9ooJLu/AnDM3pcbkn8e+PfjScXywBCsXdlEmwE=|149.22.88.58:51820"
  "8GV+0tDa6cRn8fdi2T0h0kOJ09j/wqwZmNkRem0q0UI=|g0gQj1lhsEuyJcJlzVyjq7aQmtC+/ca05vqOqvCQ/zI=|146.70.230.130:51820"
  "mNxXbJR4T9cKM3IYOHbp+7N+aa1WFuYaqI0YpKa+pEg=|ZEQHDxg/HbjznRvApyBWfUGs6T20Rvy0/DctZk6FvB4=|89.187.185.161:51820"
  "6J4kyAvFKtVFIZu4KaTpVIPIb9eqdW29G6lHRJBXllU=|jShHBnjRpU3cgm2apLl0OElwSK0fs/gJTm9nnjdO8Ec=|149.40.62.119:51820"
  "+HMkwLLgbynGfifsMk2dSWkk9fyl41EutI9Vsjj2ZXk=|KZ9UhGk5qLny663HP6xWCfyIDH2xgvu9DNH5tGYmYnw=|138.199.50.144:51820"
  "UARft8SuSAsx9i3EXQuOYpr55C0VWa7ixFgnH6l/Fk4=|eAXAQ+pjJuejhTOjyCnC39GS/8lv8Zw7Cj5u7gMzIgE=|151.243.141.166:51820"
  "8EsXHKNXdR7pNM4lN/Dl18wXZfarPnyEb5Tn+hOK00I=|LnAW4J80mzbBRPWuJyPcT1H04MElAYZus93sOG4WCFE=|146.70.230.82:51820"
  "+B0nD8F86Qz1EgnuPglmKEtdVPQeFxfbgO3E+kkwhl4=|OKHT7YYBH4VD4vmuxrpbWQtY4SIRHuibasAZthkWEzg=|146.70.230.98:51820"
  "QDNLJjX8stIOVJza9HzlHUWgF6MA9QYL+7rzAiDHbUE=|8jEgre7McUnWFLvjlQSenvYJgUGISWeNyLonrEupuDA=|146.70.230.114:51820"
  "EJaBl0BHpFVM4LF/850a5ZKDkmO+eSs5eXmAuIIzAmI=|v5X/QsIRV2BRh6XKeDk1+NOiqAZDYYTD6xL3Qiu/b2g=|151.243.141.164:51820"
  "IInph6mqE0DmcpVvdsX5K5kCAqimzgRhqB+fDrJNmXg=|qwoWn5tpqguIWdYpsIjUIMnrMT0dtxnrKwSUB4ZvMTA=|151.243.141.160:51820"
)

TOTAL=${#WG_PEERS[@]}

# ── Ensure wireproxy binary is available ──
ensure_wireproxy() {
  [ -x "$WIREPROXY" ] && return 0
  [ -x "$WIREPROXY_TMP" ] && { ln -sf "$WIREPROXY_TMP" "$WIREPROXY" 2>/dev/null; return 0; }

  local arch
  arch=$(uname -m)
  case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;;
    *) err "Unsupported arch: $arch"; return 1 ;;
  esac

  # Try multiple download methods
  local url="https://github.com/octeep/wireproxy/releases/latest/download/wireproxy_linux_${arch}.tar.gz"
  local dest="$WIREPROXY_TMP"

  log "Downloading wireproxy (${arch})..."
  # Method 1: curl
  if command -v curl &>/dev/null; then
    curl -sL --max-time 45 "$url" -o /tmp/wp.tar.gz && \
      tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
      mv /tmp/wireproxy "$dest" && chmod +x "$dest" && \
      rm -f /tmp/wp.tar.gz && \
      ln -sf "$dest" "$WIREPROXY" 2>/dev/null && \
      log "wireproxy installed via curl." && return 0
  fi
  # Method 2: wget
  if command -v wget &>/dev/null; then
    wget -qO /tmp/wp.tar.gz --timeout=45 "$url" && \
      tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
      mv /tmp/wireproxy "$dest" && chmod +x "$dest" && \
      rm -f /tmp/wp.tar.gz && \
      ln -sf "$dest" "$WIREPROXY" 2>/dev/null && \
      log "wireproxy installed via wget." && return 0
  fi

  err "Failed to download wireproxy from GitHub."
  err "URL: $url"
  warn "The VPN will not work without the wireproxy binary."
  return 1
}

# ── Write wireproxy config (HTTP CONNECT mode) ──
write_config() {
  local key="$1" peer="$2" ep="$3"
  cat > /home/node/.wireproxy.conf << CFG
[Interface]
PrivateKey = ${key}
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = ${peer}
Endpoint = ${ep}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25

[http]
BindAddress = 127.0.0.1:${TUNNEL_PORT}
CFG
  chmod 600 /home/node/.wireproxy.conf
}

# ── Start tunnel with a given peer index ──
start_tunnel() {
  local idx=$1
  local entry="${WG_PEERS[$idx]}"
  IFS='|' read -r priv_key peer_key endpoint <<< "$entry"
  local ip=$(echo "$endpoint" | cut -d: -f1)

  write_config "$priv_key" "$peer_key" "$endpoint"
  log "Starting tunnel ($((idx+1))/$TOTAL) → $ip"

  # Run in foreground, background the whole thing (no -d flag to avoid daemon PID issue)
  "$WIREPROXY" -c /home/node/.wireproxy.conf &
  local pid=$!
  echo "$pid" > "${STATE_DIR}/run/pid"
  log "wireproxy PID: $pid"

  # Wait for port to open (portable check using /dev/tcp)
  local waited=0
  while [ $waited -lt 20 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      # Process died — check exit status
      wait "$pid" 2>/dev/null || true
      err "wireproxy process exited unexpectedly."
      return 1
    fi
    # Portable port check (works even without ss/netstat)
    if (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/${TUNNEL_PORT}" 2>/dev/null); then
      log "Tunnel active (PID $pid, port $TUNNEL_PORT)."
      local ext_ip
      ext_ip=$(curl -s --max-time 5 --proxy "http://127.0.0.1:${TUNNEL_PORT}" https://icanhazip.com 2>/dev/null || echo "")
      [ -n "$ext_ip" ] && log "Exit IP: ${ext_ip}" && echo "$ext_ip" > "${STATE_DIR}/tunnel_ip"
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done

  err "Timeout waiting for tunnel (port ${TUNNEL_PORT} not listening after 20s)."
  kill "$pid" 2>/dev/null || true
  return 1
}

stop_tunnel() {
  local pf="${STATE_DIR}/run/pid"
  if [ -f "$pf" ]; then
    local old_pid; old_pid=$(cat "$pf" 2>/dev/null || echo "")
    [ -n "$old_pid" ] && kill "$old_pid" 2>/dev/null || true
  fi
  pkill -x wireproxy 2>/dev/null || true
  rm -f "$pf" 2>/dev/null || true
  sleep 1
}

# ── Verify actual connectivity through the tunnel ──
verify_tunnel() {
  local test_url="${1:-https://icanhazip.com}"
  # Use curl with HTTP CONNECT proxy to verify
  local ip
  ip=$(curl -s --max-time 10 --proxy "http://127.0.0.1:${TUNNEL_PORT}" "$test_url" 2>/dev/null || echo "")
  if [ -n "$ip" ] && [ "$ip" != "" ]; then
    log "Tunnel verified: exit IP = ${ip}"
    echo "$ip" > "${STATE_DIR}/tunnel_ip"
    return 0
  fi
  return 1
}

# ── Main loop ──
run_service() {
  mkdir -p "$STATE_DIR" "${STATE_DIR}/run"
  chown -R 1000:1000 "$STATE_DIR" 2>/dev/null || true

  log "Initializing Proton VPN tunnel (${TOTAL} configs, rotate ${ROTATE}min)..."

  if ! ensure_wireproxy; then
    echo "failed (binary)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  local idx=0
  local failed_count=0
  local max_fails=${TOTAL}

  while true; do
    stop_tunnel

    if start_tunnel "$idx"; then
      failed_count=0
      echo "connected" > "$STATUS_FILE"
      chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true

      # Verify the tunnel works
      verify_tunnel || warn "Tunnel up but verification failed (exit IP check)."
    else
      failed_count=$((failed_count + 1))
      echo "failed (attempt ${failed_count})" > "$STATUS_FILE"
      chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true

      if [ $failed_count -ge $max_fails ]; then
        err "All ${TOTAL} configs failed. Giving up."
        echo "failed (all)" > "$STATUS_FILE"
        return 1
      fi
    fi

    log "Next rotation in ${ROTATE} min..."
    sleep $((ROTATE * 60))
    idx=$(( (idx + 1) % TOTAL ))
  done
}

# ── CLI ──
case "${1:-service}" in
  service) run_service ;;
  status)
    echo "status: $(cat "$STATUS_FILE" 2>/dev/null || echo 'unknown')"
    echo "tunnel_ip: $(cat "${STATE_DIR}/tunnel_ip" 2>/dev/null || echo 'unknown')"
    echo "wireproxy_bin: $([ -x "$WIREPROXY" ] && echo ok || echo missing)"
    echo "wireproxy_pid: $(cat "${STATE_DIR}/run/pid" 2>/dev/null || echo 'none')"
    echo "port_${TUNNEL_PORT}: $(ss -tlnp 2>/dev/null | grep -q ":${TUNNEL_PORT} " && echo listening || echo not listening)"
    ;;
  check)
    [ -x "$WIREPROXY" ] && echo "wireproxy: ok" || echo "wireproxy: missing"
    echo "configs: ${TOTAL}"
    ss -tlnp 2>/dev/null | grep ":${TUNNEL_PORT} " || echo "port ${TUNNEL_PORT}: not listening"
    ;;
  *) echo "Usage: $0 {service|status|check}" ;;
esac
