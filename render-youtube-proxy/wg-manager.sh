#!/bin/bash
# ════════════════════════════════════════════════════════════════
# WireGuard Tunnel Manager — wireproxy (userspace, no TUN/NET_ADMIN)
#     HTTP CONNECT proxy on port 25345 for yt-dlp.
#
#     4 built-in Proton VPN FREE WireGuard configs (Singapore).
#     Env vars WG_CONFIGS / WG_* override the built-in defaults.
# ════════════════════════════════════════════════════════════════

set -euo pipefail

log()  { echo "[wg] $(date '+%Y-%m-%d %H:%M:%S') $*" >&2; }
err()  { echo "[wg] ERROR: $*" >&2; }
warn() { echo "[wg] WARNING: $*" >&2; }

TUNNEL_PORT="${WG_TUNNEL_PORT:-25345}"
STATE_DIR="/tmp/wireguard"
STATUS_FILE="${STATE_DIR}/status"
IP_FILE="${STATE_DIR}/exit_ip"
WIREPROXY="/usr/local/bin/wireproxy"

HEALTH_INTERVAL=30
HEALTH_THRESHOLD=2
HEALTH_TEST_URL="${HEALTH_TEST_URL:-https://icanhazip.com}"

# ── 4 built-in Proton VPN FREE WireGuard configs (Singapore) ──
# Format: privateKey|peerPublicKey|endpoint
BUILTIN_PEERS=(
  "IFVH9u+4DH8vary70GyVbt5gqAYpiahEtF+UrDrqr0I=|DU0jJf1tLDu9Nr84tFt1Eph27zsvI3Gu5dkwTGyE9Wk=|103.216.221.73:51820"
  "qNk4thdxYB858+2fgO56r0jJ8jgRo+p25tmPRiXubXQ=|LzDybSqRbDLpmigYBYbCHyh9fMfphvcEYpV39GvTgE4=|103.216.221.69:51820"
  "KDKAhqj/k9Galx6MYdt1GfUam7dxzoorUuQ6ENERInI=|wooCicf2PLNZjvDxVMVc/nrvFsFnNAU4n+AnKWVz8mg=|149.50.211.149:51820"
  "2N2s6TElhFywIgBJujvlFPMpeHassktBpwlBBBQSLU0=|o+vYNpIDzf302SLUBLAG9zBf+M3nBBoCq/uei1M/wws=|149.50.211.159:51820"
)

# ── Ensure wireproxy binary ──
ensure_wireproxy() {
  [ -x "$WIREPROXY" ] && return 0

  local arch
  arch=$(uname -m)
  case "$arch" in x86_64|amd64) arch="amd64" ;; aarch64|arm64) arch="arm64" ;;
    *) err "Unsupported arch: $arch"; return 1 ;;
  esac

  local url="https://github.com/octeep/wireproxy/releases/latest/download/wireproxy_linux_${arch}.tar.gz"
  log "Downloading wireproxy (${arch})..."
  curl -sL --max-time 45 "$url" -o /tmp/wp.tar.gz && \
    tar -xzf /tmp/wp.tar.gz -C /tmp/ && \
    mv /tmp/wireproxy "$WIREPROXY" && chmod +x "$WIREPROXY" && \
    rm -f /tmp/wp.tar.gz && \
    log "wireproxy installed." && return 0

  err "Failed to download wireproxy."
  return 1
}

# ── Parse configs: env vars → built-in defaults ──
# Priority: WG_CONFIGS JSON > WG_PRIVATE_KEY trio > built-in peers
parse_configs() {
  # 1. WG_CONFIGS JSON array
  if [ -n "${WG_CONFIGS:-}" ]; then
    echo "$WG_CONFIGS"
    return
  fi

  # 2. Single config from individual env vars
  if [ -n "${WG_PRIVATE_KEY:-}" ] && [ -n "${WG_PEER_PUBLIC_KEY:-}" ] && [ -n "${WG_ENDPOINT:-}" ]; then
    printf '[{"privateKey":"%s","peerPublicKey":"%s","endpoint":"%s"}]' \
      "$WG_PRIVATE_KEY" "$WG_PEER_PUBLIC_KEY" "$WG_ENDPOINT"
    return
  fi

  # 3. Built-in Proton VPN FREE configs
  log "No WG_* env vars — using built-in Proton VPN FREE configs (${#BUILTIN_PEERS[@]} peers)"
  local first=true
  printf '['
  for entry in "${BUILTIN_PEERS[@]}"; do
    $first || printf ','
    first=false
    IFS='|' read -r key peer ep <<< "$entry"
    printf '{"privateKey":"%s","peerPublicKey":"%s","endpoint":"%s"}' "$key" "$peer" "$ep"
  done
  printf ']'
}

# ── Write wireproxy config (HTTP CONNECT mode) ──
write_config() {
  local key="$1" peer="$2" ep="$3" idx="$4"
  local cfg_file="${STATE_DIR}/wireproxy-${idx}.conf"
  cat > "$cfg_file" << CFG
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
  chmod 600 "$cfg_file"
  echo "$cfg_file"
}

# ── Start wireproxy with a given config index ──
start_tunnel() {
  local idx=$1
  local configs_json="$2"
  local cfg
  cfg=$(echo "$configs_json" | python3 -c "
import sys,json
c=json.load(sys.stdin)
print(c[$idx]['privateKey'])
print(c[$idx]['peerPublicKey'])
print(c[$idx]['endpoint'])
" 2>/dev/null) || return 1

  local key peer ep
  key=$(echo "$cfg" | sed -n '1p')
  peer=$(echo "$cfg" | sed -n '2p')
  ep=$(echo "$cfg" | sed -n '3p')

  local cfg_file
  cfg_file=$(write_config "$key" "$peer" "$ep" "$idx")
  log "Starting tunnel ($((idx+1))) → $(echo "$ep" | cut -d: -f1)"

  "$WIREPROXY" -c "$cfg_file" &
  local pid=$!
  echo "$pid" > "${STATE_DIR}/pid"
  log "wireproxy PID: ${pid}"

  local waited=0
  while [ $waited -lt 15 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      err "wireproxy exited."
      return 1
    fi
    if (timeout 1 bash -c "echo > /dev/tcp/127.0.0.1/${TUNNEL_PORT}" 2>/dev/null); then
      local ext_ip
      ext_ip=$(curl -s --max-time 10 --proxy "http://127.0.0.1:${TUNNEL_PORT}" "${HEALTH_TEST_URL}" 2>/dev/null || echo "")
      if [ -n "$ext_ip" ]; then
        echo "$ext_ip" > "$IP_FILE"
        log "Tunnel active — exit IP: ${ext_ip}"
      else
        warn "Tunnel port open but exit IP check failed."
      fi
      return 0
    fi
    sleep 1
    waited=$((waited + 1))
  done

  err "Timeout waiting for tunnel port ${TUNNEL_PORT}."
  kill "$pid" 2>/dev/null || true
  return 1
}

stop_tunnel() {
  local pf="${STATE_DIR}/pid"
  if [ -f "$pf" ]; then
    local old_pid; old_pid=$(cat "$pf" 2>/dev/null || echo "")
    [ -n "$old_pid" ] && kill "$old_pid" 2>/dev/null || true
  fi
  pkill -x wireproxy 2>/dev/null || true
  rm -f "$pf" 2>/dev/null || true
  sleep 1
}

health_check() {
  local ip
  ip=$(curl -s --max-time 10 --proxy "http://127.0.0.1:${TUNNEL_PORT}" "${HEALTH_TEST_URL}" 2>/dev/null || echo "")
  if [ -n "$ip" ]; then
    echo "$ip" > "$IP_FILE"
    return 0
  fi
  return 1
}

# ── Main ──
main() {
  mkdir -p "$STATE_DIR"

  local configs_json
  configs_json=$(parse_configs)

  local total
  total=$(echo "$configs_json" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "1")
  log "Loaded $total WireGuard config(s)"

  ensure_wireproxy || { echo "failed (binary)" > "$STATUS_FILE"; return 1; }

  local idx=0
  local failures=0
  local max_fail=$total

  while true; do
    stop_tunnel

    if start_tunnel "$idx" "$configs_json"; then
      failures=0
      echo "connected" > "$STATUS_FILE"

      local elapsed=0
      local max_seconds=$(( ${WG_ROTATE_INTERVAL:-30} * 60 ))

      while [ $elapsed -lt $max_seconds ]; do
        sleep 5
        elapsed=$((elapsed + 5))

        if [ -f /tmp/wg-force-rotate ]; then
          rm -f /tmp/wg-force-rotate
          log "Manual rotation requested."
          break
        fi

        if [ $((elapsed % HEALTH_INTERVAL)) -eq 0 ]; then
          if ! kill -0 "$(cat ${STATE_DIR}/pid 2>/dev/null)" 2>/dev/null; then
            warn "wireproxy died. Rotating..."
            break
          fi
          if health_check; then
            failures=0
          else
            failures=$((failures + 1))
            if [ "$failures" -ge "$HEALTH_THRESHOLD" ]; then
              warn "Health threshold reached. Rotating..."
              break
            fi
          fi
        fi
      done
    else
      failures=$((failures + 1))
      if [ "$failures" -ge "$max_fail" ]; then
        err "All configs failed. Tunnel disabled."
        echo "failed" > "$STATUS_FILE"
        return 1
      fi
    fi

    idx=$(( (idx + 1) % total ))
    log "Rotating to config $((idx+1))/${total}..."
  done
}

main "$@"
