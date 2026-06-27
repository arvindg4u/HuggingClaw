#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 🛡️  Proton VPN Manager — WireGuard tunnel via wireproxy.
#     Userspace — no TUN/NET_ADMIN needed. Works on HF Spaces.
#
#     4 Singapore Proton VPN FREE WireGuard configs.
#     Uses HTTP CONNECT (standard HTTPS tunnel, not SOCKS5).
#
#     Features:
#     - 30-min automatic IP rotation
#     - 60-sec health check (curl via tunnel → icanhazip.com)
#     - 2 consecutive failures → immediate auto-rotate to next peer
#     - WireGuard process watchdog
# ════════════════════════════════════════════════════════════════

set -euo pipefail

log()  { echo "[hc-vpn] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
err()  { echo "[hc-vpn] ERROR: $*" >&2; }
warn() { echo "[hc-vpn] WARNING: $*" >&2; }

ROTATE="${PROTONVPN_ROTATE_INTERVAL:-30}"
TUNNEL_PORT=25345
STATE_DIR="/home/node/.protonvpn"
STATUS_FILE="${STATE_DIR}/status"
HEALTH_FILE="${STATE_DIR}/health"
TUNNEL_IP_FILE="${STATE_DIR}/tunnel_ip"
WIREPROXY="/usr/local/bin/wireproxy"
WIREPROXY_TMP="/tmp/wireproxy"

# Health check config
HEALTH_INTERVAL=60          # check every 60 seconds
HEALTH_THRESHOLD=2          # 2 consecutive failures = trigger rotate
HEALTH_TEST_URL="${HEALTH_TEST_URL:-https://icanhazip.com}"

# ── 4 Singapore Proton VPN FREE WireGuard configs ──
declare -a WG_PEERS=(
  "IFVH9u+4DH8vary70GyVbt5gqAYpiahEtF+UrDrqr0I=|DU0jJf1tLDu9Nr84tFt1Eph27zsvI3Gu5dkwTGyE9Wk=|103.216.221.73:51820"
  "qNk4thdxYB858+2fgO56r0jJ8jgRo+p25tmPRiXubXQ=|LzDybSqRbDLpmigYBYbCHyh9fMfphvcEYpV39GvTgE4=|103.216.221.69:51820"
  "KDKAhqj/k9Galx6MYdt1GfUam7dxzoorUuQ6ENERInI=|wooCicf2PLNZjvDxVMVc/nrvFsFnNAU4n+AnKWVz8mg=|149.50.211.149:51820"
  "2N2s6TElhFywIgBJujvlFPMpeHassktBpwlBBBQSLU0=|o+vYNpIDzf302SLUBLAG9zBf+M3nBBoCq/uei1M/wws=|149.50.211.159:51820"
)

TOTAL=${#WG_PEERS[@]}

# ── Helpers ──
write_health() { echo "$1" > "$HEALTH_FILE"; chown 1000:1000 "$HEALTH_FILE" 2>/dev/null || true; }
write_status() { echo "$1" > "$STATUS_FILE"; chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true; }
write_tunnel_ip() { echo "$1" > "$TUNNEL_IP_FILE"; chown 1000:1000 "$TUNNEL_IP_FILE" 2>/dev/null || true; }

# ── Ensure wireproxy binary is available ──
ensure_wireproxy() {
  [ -x "$WIREPROXY" ] && return 0
  [ -x "$WIREPROXY_TMP" ] && { ln -sf "$WIREPROXY_TMP" "$WIREPROXY" 2>/dev/null; return 0; }

  local arch
  arch=$(uname -m)
  case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;;
    *) err "Unsupported arch: $arch"; return 1 ;;
  esac

  local url="https://github.com/octeep/wireproxy/releases/latest/download/wireproxy_linux_${arch}.tar.gz"
  local dest="$WIREPROXY_TMP"

  log "Downloading wireproxy (${arch})..."
  if command -v curl &>/dev/null; then
    curl -sL --max-time 45 "$url" -o /tmp/wp.tar.gz && \
      tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
      mv /tmp/wireproxy "$dest" && chmod +x "$dest" && \
      rm -f /tmp/wp.tar.gz && \
      ln -sf "$dest" "$WIREPROXY" 2>/dev/null && \
      log "wireproxy installed via curl." && return 0
  fi
  if command -v wget &>/dev/null; then
    wget -qO /tmp/wp.tar.gz --timeout=45 "$url" && \
      tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
      mv /tmp/wireproxy "$dest" && chmod +x "$dest" && \
      rm -f /tmp/wp.tar.gz && \
      ln -sf "$dest" "$WIREPROXY" 2>/dev/null && \
      log "wireproxy installed via wget." && return 0
  fi
  err "Failed to download wireproxy from GitHub."
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
  log "Starting tunnel ($((idx+1))/$TOTAL) → ${ip}"

  "$WIREPROXY" -c /home/node/.wireproxy.conf &
  local pid=$!
  echo "$pid" > "${STATE_DIR}/run/pid"
  log "wireproxy PID: ${pid}"

  # Wait for port to open (portable /dev/tcp check)
  local waited=0
  while [ $waited -lt 20 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      err "wireproxy process exited unexpectedly."
      return 1
    fi
    if (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/${TUNNEL_PORT}" 2>/dev/null); then
      log "Tunnel active (PID ${pid}, port ${TUNNEL_PORT})."
      # Verify exit IP immediately
      local ext_ip
      ext_ip=$(curl -s --max-time 10 --proxy "http://127.0.0.1:${TUNNEL_PORT}" \
        "${HEALTH_TEST_URL}" 2>/dev/null || echo "")
      if [ -n "$ext_ip" ]; then
        log "Exit IP: ${ext_ip}"
        write_tunnel_ip "$ext_ip"
      else
        warn "Exit IP check returned empty — tunnel may be degraded."
      fi
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done
  err "Timeout waiting for tunnel (port ${TUNNEL_PORT} not listening after 20s)."
  kill "$pid" 2>/dev/null || true
  return 1
}

# ── Stop wireproxy ──
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

# ── Health check: verify tunnel can reach external service ──
# Returns 0 if healthy, 1 if dead.
health_check() {
  local ip
  ip=$(curl -s --max-time 10 --proxy "http://127.0.0.1:${TUNNEL_PORT}" \
    "${HEALTH_TEST_URL}" 2>/dev/null || echo "")
  if [ -n "$ip" ]; then
    write_tunnel_ip "$ip"
    return 0
  fi
  return 1
}

# ── Verify wireproxy process is alive ──
wireproxy_alive() {
  local pf="${STATE_DIR}/run/pid"
  [ -f "$pf" ] || return 1
  local pid; pid=$(cat "$pf" 2>/dev/null || echo "")
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && return 0
  return 1
}

# ── Main loop with periodic health checks ──
run_service() {
  mkdir -p "$STATE_DIR" "${STATE_DIR}/run"
  chown -R 1000:1000 "$STATE_DIR" 2>/dev/null || true

  log "Initializing Proton VPN tunnel (${TOTAL} configs, rotate ${ROTATE}min)."
  log "Health check every ${HEALTH_INTERVAL}s, auto-rotate after ${HEALTH_THRESHOLD} failures."

  if ! ensure_wireproxy; then
    write_status "failed (binary)"
    return 1
  fi

  local idx=0
  local consecutive_failures=0
  local total_failed_configs=0
  local max_fails=${TOTAL}

  while true; do
    stop_tunnel

    if start_tunnel "$idx"; then
      consecutive_failures=0
      write_status "connected"
      write_health "ok"

      # ── Inner loop: health checks + rotation timer ──
      local elapsed_seconds=0
      local max_seconds=$((ROTATE * 60))

      while [ $elapsed_seconds -lt $max_seconds ]; do
        sleep 5
        elapsed_seconds=$((elapsed_seconds + 5))

        # Check for manual rotate flag (from dashboard button)
        if [ -f /tmp/protonvpn-force-rotate ]; then
          rm -f /tmp/protonvpn-force-rotate
          warn "Manual rotation requested. Rotating..."
          write_health "rotating (manual)"
          write_status "rotating"
          break
        fi

        # Run health checks at configured interval
        if [ $((elapsed_seconds % HEALTH_INTERVAL)) -eq 0 ]; then
          local elapsed_minutes=$((elapsed_seconds / 60))

          # 1. Check wireproxy process is alive
          if ! wireproxy_alive; then
            warn "wireproxy process died (elapsed ${elapsed_minutes}m). Rotating..."
            write_health "dead (process)"
            break
          fi

          # 2. Check tunnel connectivity
          if health_check; then
            if [ "$consecutive_failures" -gt 0 ]; then
              log "Health recovered after ${consecutive_failures} failure(s)."
              consecutive_failures=0
              write_health "ok"
              write_status "connected"
            fi
          else
            consecutive_failures=$((consecutive_failures + 1))
            write_health "fail (${consecutive_failures}/${HEALTH_THRESHOLD})"
            warn "Health check ${consecutive_failures}/${HEALTH_THRESHOLD} failed (elapsed ${elapsed_minutes}m)."

            if [ "$consecutive_failures" -ge "$HEALTH_THRESHOLD" ]; then
              warn "Health threshold reached! Rotating to next peer..."
              write_health "rotating (threshold)"
              break
            fi
          fi
        fi
      done
    else
      # Tunnel failed to start
      total_failed_configs=$((total_failed_configs + 1))
      write_status "failed (attempt ${total_failed_configs})"
      write_health "start-failed"

      if [ "$total_failed_configs" -ge "$max_fails" ]; then
        err "All ${TOTAL} configs failed. Giving up."
        write_status "failed (all)"
        write_health "dead (exhausted)"
        return 1
      fi
    fi

    # Rotate to next peer
    idx=$(( (idx + 1) % TOTAL ))
    log "Rotating to config $((idx+1))/${TOTAL}..."
  done
}

# ── CLI ──
case "${1:-service}" in
  service) run_service ;;
  status)
    echo "status: $(cat "$STATUS_FILE" 2>/dev/null || echo 'unknown')"
    echo "health: $(cat "$HEALTH_FILE" 2>/dev/null || echo 'unknown')"
    echo "tunnel_ip: $(cat "$TUNNEL_IP_FILE" 2>/dev/null || echo 'unknown')"
    echo "wireproxy_bin: $([ -x "$WIREPROXY" ] && echo ok || echo missing)"
    echo "wireproxy_pid: $(cat "${STATE_DIR}/run/pid" 2>/dev/null || echo 'none')"
    echo "port_${TUNNEL_PORT}: $(ss -tlnp 2>/dev/null | grep -q ":${TUNNEL_PORT} " && echo listening || echo not listening)"
    echo "configs_total: ${TOTAL}"
    echo "health_interval: ${HEALTH_INTERVAL}s"
    echo "health_threshold: ${HEALTH_THRESHOLD}"
    ;;
  check)
    echo "wireproxy: $([ -x "$WIREPROXY" ] && echo ok || echo missing)"
    echo "configs: ${TOTAL}"
    echo "health_interval: ${HEALTH_INTERVAL}s"
    echo "health_threshold: ${HEALTH_THRESHOLD}"
    ss -tlnp 2>/dev/null | grep ":${TUNNEL_PORT} " || echo "port ${TUNNEL_PORT}: not listening"
    ;;
  *) echo "Usage: $0 {service|status|check}" ;;
esac
