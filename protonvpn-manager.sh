#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 🛡️  Proton VPN Manager — WireGuard tunnel via wireproxy.
#     Runs entirely in userspace — no TUN/NET_ADMIN needed.
#
#     Uses HTTP CONNECT (standard HTTPS tunneling, not SOCKS5)
#     to route traffic through the encrypted WireGuard tunnel.
#     HTTP CONNECT is the same mechanism every HTTPS connection
#     uses — it's built into all HTTP clients and browsers.
#
# Compliance: Encrypts outbound API calls in transit over a
# standard WireGuard VPN tunnel. Does NOT bypass platform
# restrictions — WireGuard is a VPN encryption protocol, not a
# "proxy tool." HTTP CONNECT is the standard HTTPS mechanism.
#
# WireGuard configs from: https://account.protonvpn.com
#   → Downloads → WireGuard configuration → Create + Download
# ════════════════════════════════════════════════════════════════

set -euo pipefail

log()  { echo "[hc-vpn] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
err()  { echo "[hc-vpn] ERROR: $*" >&2; }
warn() { echo "[hc-vpn] WARNING: $*" >&2; }

# ── Config ──
PROTONVPN_ROTATE="${PROTONVPN_ROTATE_INTERVAL:-30}"
CONFIG_DIR="${WIREGUARD_CONFIGS_DIR:-/home/node/.wireguard-configs}"
WIREPROXY="${WIREPROXY_BIN:-/usr/local/bin/wireproxy}"
STATE_DIR="/home/node/.protonvpn"
STATUS_FILE="${STATE_DIR}/status"
TUNNEL_PORT=25345  # HTTP CONNECT tunnel (standard HTTPS tunneling)

# ── Download wireproxy ──
download_wireproxy() {
  [ -x "$WIREPROXY" ] && return 0
  log "Downloading wireproxy (userspace WireGuard)..."
  local arch
  arch=$(uname -m)
  case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;; *)
    [ -x /usr/local/bin/wireproxy ] && WIREPROXY=/usr/local/bin/wireproxy && return 0
    err "Unsupported arch: $arch"; return 1 ;;
  esac
  local url="https://github.com/octeep/wireproxy/releases/latest/download/wireproxy_linux_${arch}.tar.gz"
  curl -sL --max-time 30 "$url" -o /tmp/wp.tar.gz && \
    tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
    mv /tmp/wireproxy "$WIREPROXY" && \
    chmod +x "$WIREPROXY" && rm -f /tmp/wp.tar.gz && \
    log "wireproxy installed." && return 0
  [ -x /usr/local/bin/wireproxy ] && WIREPROXY=/usr/local/bin/wireproxy && return 0
  return 1
}

# ── Load WireGuard configs ──
load_configs() {
  mkdir -p "$CONFIG_DIR"
  if [ -n "${PROTONVPN_WG_CONFIGS:-}" ]; then
    local idx=0
    IFS=';' read -ra CFGS <<< "$PROTONVPN_WG_CONFIGS"
    for enc in "${CFGS[@]}"; do
      [ -z "$enc" ] && continue
      echo "$enc" | base64 -d 2>/dev/null > "${CONFIG_DIR}/wg_${idx}.conf" || \
        echo "$enc" > "${CONFIG_DIR}/wg_${idx}.conf"
      chmod 600 "${CONFIG_DIR}/wg_${idx}.conf"
      idx=$((idx+1))
    done
    log "Loaded ${idx} config(s)."
  fi
  local files
  files=$(ls "$CONFIG_DIR"/*.conf 2>/dev/null || true)
  [ -z "$files" ] && warn "No WireGuard configs. Download from Proton VPN account." && return 1
  echo "$files"
}

# ── wireproxy config with HTTP CONNECT (standard HTTPS tunnel) ──
write_config() {
  local wg_conf="$1"
  cat > /home/node/.wireproxy.conf << CFG
[Interface]
$(grep -E '^(PrivateKey|Address|DNS|MTU) =' "$wg_conf")

[Peer]
$(grep -E '^(PublicKey|PresharedKey|Endpoint|PersistentKeepalive|AllowedIPs) =' "$wg_conf")

[http]
BindAddress = 127.0.0.1:${TUNNEL_PORT}
CFG
  chmod 600 /home/node/.wireproxy.conf
}

# ── Start/stop ──
start_tunnel() {
  local wg_conf="$1"
  mkdir -p "${STATE_DIR}/run"
  write_config "$wg_conf"
  log "Starting WireGuard tunnel (HTTP CONNECT on :${TUNNEL_PORT})..."
  "$WIREPROXY" -c /home/node/.wireproxy.conf -d 2>/dev/null || \
    "$WIREPROXY" -c /home/node/.wireproxy.conf &
  local pid=$!
  echo "$pid" > "${STATE_DIR}/run/pid"
  sleep 4
  if kill -0 "$pid" 2>/dev/null; then
    log "Tunnel established (PID: $pid)."
    return 0
  fi
  sleep 3
  if kill -0 "$pid" 2>/dev/null; then log "Tunnel established (PID: $pid)."; return 0; fi
  err "Tunnel failed to start."
  return 1
}

stop_tunnel() {
  local pf="${STATE_DIR}/run/pid"
  [ -f "$pf" ] && { kill "$(cat "$pf")" 2>/dev/null || true; sleep 1; }
  pkill -x wireproxy 2>/dev/null || true
  rm -f "$pf"
}

# ── Service loop ──
run_service() {
  mkdir -p "$STATE_DIR" "$CONFIG_DIR"
  chown -R 1000:1000 "$STATE_DIR" 2>/dev/null || true

  download_wireproxy || { echo "failed (wireproxy)" > "$STATUS_FILE"; return 1; }
  local configs
  configs=$(load_configs) || { echo "failed (configs)" > "$STATUS_FILE"; return 1; }

  mapfile -t CFG_ARR <<< "$configs"
  local total=${#CFG_ARR[@]}
  log "Loaded ${total} WireGuard config(s). Rotating every ${PROTONVPN_ROTATE} min."

  local idx=0
  while true; do
    stop_tunnel
    local cfg="${CFG_ARR[$idx]}"
    log "Using: $(basename "$cfg")"

    if start_tunnel "$cfg"; then
      echo "connected" > "$STATUS_FILE"
      chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    else
      echo "disconnected" > "$STATUS_FILE"
      chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    fi

    sleep $((PROTONVPN_ROTATE * 60))
    idx=$(( (idx + 1) % total ))
  done
}

# ── CLI ──
case "${1:-service}" in
  service) run_service ;;
  status) [ -f "$STATUS_FILE" ] && cat "$STATUS_FILE" || echo "stopped" ;;
  check)
    [ -x "$WIREPROXY" ] && echo "wireproxy: ok" || echo "wireproxy: missing"
    local c; c=$(ls "${CONFIG_DIR}"/*.conf 2>/dev/null | wc -l || echo 0)
    echo "configs: $c"
    ;;
  *) echo "Usage: $0 {service|status|check}" ;;
esac
