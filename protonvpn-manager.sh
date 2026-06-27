#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 🛡️  Proton VPN Manager — Benign privacy layer for outbound API
#     traffic. Encrypts the app's HTTP/HTTPS requests to LLM
#     providers.
#
# Compliance: This is for protecting API keys and payloads in
# transit. Do NOT use for:
#   - Spam, abuse, or cryptomining
#   - Bypassing platform restrictions
#   - Unauthorized access to systems
#   - Any purpose violating HF Spaces TOS
# ════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Logging ──
log()  { echo "[hc-vpn] $(date '+%Y-%m-%d %H:%M:%S') $*"; }
err()  { echo "[hc-vpn] ERROR: $*" >&2; }
warn() { echo "[hc-vpn] WARNING: $*" >&2; }

# ── Config from env ──
PROTONVPN_USERNAME="${PROTONVPN_USERNAME:-}"
PROTONVPN_PASSWORD="${PROTONVPN_PASSWORD:-}"
OPENVPN_USERNAME="${OPENVPN_USERNAME:-$PROTONVPN_USERNAME}"
OPENVPN_PASSWORD="${OPENVPN_PASSWORD:-$PROTONVPN_PASSWORD}"
# Tier: 1=Free, 2=Basic, 3=Plus, 4=Visionary
PROTONVPN_TIER="${PROTONVPN_TIER:-1}"
PROTONVPN_ROTATE_INTERVAL="${PROTONVPN_ROTATE_INTERVAL:-30}"
PROTONVPN_COUNTRY="${PROTONVPN_COUNTRY:-}"
PROTONVPN_PROTOCOL="${PROTONVPN_PROTOCOL:-udp}"

STATE_DIR="/home/node/.protonvpn"
PID_FILE="${STATE_DIR}/pid"
STATUS_FILE="${STATE_DIR}/status"

# ── Helper: check if running on HF Spaces (no NET_ADMIN) ──
detect_hf_spaces() {
  [ -n "${SPACE_ID:-}" ] || [ -n "${HF_SPACE:-}" ] || [ -n "${HUGGINGFACE_SPACE:-}" ]
}

check_capabilities() {
  # Quick check: can we see network interfaces?
  if ! command -v ip &>/dev/null; then
    warn "'ip' command not found."
    return 1
  fi
  if ! ip link show lo &>/dev/null 2>&1; then
    warn "Cannot access network interfaces (no NET_ADMIN?)."
    return 1
  fi
  # Check /dev/net/tun
  if [ ! -e /dev/net/tun ]; then
    warn "/dev/net/tun not found. Attempting to create..."
    mkdir -p /dev/net 2>/dev/null || true
    mknod /dev/net/tun c 10 200 2>/dev/null || true
  fi
  if [ ! -e /dev/net/tun ]; then
    warn "TUN device unavailable — VPN tunnel cannot be created."
    return 1
  fi
  # Check tun module
  if ! lsmod 2>/dev/null | grep -q tun; then
    # Module might be built-in; try creating a test tunnel
    if ip tuntap add mode tun test_tun 2>/dev/null; then
      ip tuntap del mode tun test_tun 2>/dev/null || true
      return 0
    fi
    warn "TUN module not available — VPN may not work."
    return 1
  fi
  return 0
}

# ── Install community CLI (if missing) ──
install_cli() {
  if command -v protonvpn &>/dev/null; then
    log "Proton VPN CLI already installed."
    return 0
  fi
  log "Installing Proton VPN Community CLI (headless-compatible)..."
  pip3 install --no-cache-dir --break-system-packages \
    "git+https://github.com/jonasjancarik/protonvpn-cli-community.git@latest" 2>&1 | tail -3
  if ! command -v protonvpn &>/dev/null; then
    err "Failed to install Proton VPN CLI."
    return 1
  fi
  log "Proton VPN CLI installed."
}

# ── Initialize CLI with credentials ──
init_cli() {
  if [ -z "$PROTONVPN_USERNAME" ] || [ -z "$PROTONVPN_PASSWORD" ]; then
    err "PROTONVPN_USERNAME and PROTONVPN_PASSWORD must be set."
    return 1
  fi

  log "Initializing Proton VPN (tier ${PROTONVPN_TIER}, protocol ${PROTONVPN_PROTOCOL})..."

  # Use the same init syntax as the official Docker entrypoint
  timeout 30 protonvpn init \
    --username "$PROTONVPN_USERNAME" \
    --password "$PROTONVPN_PASSWORD" \
    --tier "$PROTONVPN_TIER" \
    --protocol "$PROTONVPN_PROTOCOL" \
    --openvpn-username "$OPENVPN_USERNAME" \
    --openvpn-password "$OPENVPN_PASSWORD" \
    --force 2>&1 | tail -5 || {
    local rc=$?
    if [ $rc -eq 124 ]; then
      err "protonvpn init timed out (30s)."
    else
      err "protonvpn init failed (exit $rc)."
    fi
    # Check for logs
    if [ -f ~/.pvpn-cli/protonvpn-cli.log ]; then
      err "Last 10 lines of CLI log:"
      tail -10 ~/.pvpn-cli/protonvpn-cli.log 2>/dev/null | while IFS= read -r line; do err "  $line"; done
    fi
    return 1
  }

  # Verify serverinfo.json was created
  if [ ! -f ~/.pvpn-cli/serverinfo.json ]; then
    err "serverinfo.json not found after init — server data pull likely failed."
    if [ -f ~/.pvpn-cli/protonvpn-cli.log ]; then
      err "Last 15 lines of CLI log:"
      tail -15 ~/.pvpn-cli/protonvpn-cli.log 2>/dev/null | while IFS= read -r line; do err "  $line"; done
    fi
    return 1
  fi

  log "Proton VPN initialized successfully."
}

# ── Connect to VPN ──
connect() {
  log "Connecting to Proton VPN..."

  # Disconnect any existing session first
  protonvpn disconnect 2>/dev/null || true
  sleep 2

  local connect_args
  if [ -n "$PROTONVPN_COUNTRY" ]; then
    log "Connecting to fastest server in: ${PROTONVPN_COUNTRY}"
    connect_args="--cc $PROTONVPN_COUNTRY"
  else
    log "Connecting to fastest available server..."
    connect_args="--fastest"
  fi

  if ! timeout 60 protonvpn connect $connect_args 2>&1 | tail -5; then
    err "protonvpn connect failed or timed out."
    return 1
  fi

  # Verify
  sleep 3
  local status
  status=$(protonvpn status 2>&1 || echo "Disconnected")
  if echo "$status" | grep -qi "Connected"; then
    local vpn_ip
    vpn_ip=$(curl -s --max-time 5 https://icanhazip.com 2>/dev/null || echo "unknown")
    log "VPN connected. Exit IP: ${vpn_ip}"
    echo "connected" > "$STATUS_FILE"
    echo "$vpn_ip" > "${STATE_DIR}/last_ip"
    chown 1000:1000 "$STATUS_FILE" "${STATE_DIR}/last_ip" 2>/dev/null || true
    return 0
  else
    err "Connection verification failed. Status: ${status}"
    echo "disconnected" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi
}

# ── Disconnect ──
disconnect() {
  log "Disconnecting..."
  timeout 15 protonvpn disconnect 2>&1 | tail -2 || true
  echo "disconnected" > "$STATUS_FILE"
  chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
  sleep 2
}

# ── Rotate server ──
rotate() {
  log "Rotating VPN server..."
  local old_ip
  old_ip=$(cat "${STATE_DIR}/last_ip" 2>/dev/null || echo "unknown")
  disconnect
  sleep 3
  connect || true
  local new_ip
  new_ip=$(cat "${STATE_DIR}/last_ip" 2>/dev/null || echo "unknown")
  if [ "$old_ip" != "$new_ip" ] && [ "$new_ip" != "unknown" ]; then
    log "IP changed: ${old_ip} → ${new_ip}"
  elif [ "$old_ip" = "$new_ip" ]; then
    warn "IP unchanged after rotation."
  fi
}

# ── Main service loop ──
run_service() {
  mkdir -p "$STATE_DIR"
  chown -R 1000:1000 "$STATE_DIR" 2>/dev/null || true

  # Check HF Spaces environment
  if detect_hf_spaces; then
    warn "HuggingFace Space detected — missing NET_ADMIN / TUN device."
    warn "Proton VPN in-container requires --cap-add=NET_ADMIN and /dev/net/tun."
    warn "HF Spaces does not support this. VPN will be skipped."
    echo "skipped (hf-spaces)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  # Check capabilities
  if ! check_capabilities; then
    warn "Missing VPN capabilities (NET_ADMIN / TUN)."
    warn "Run with: --cap-add=NET_ADMIN --device /dev/net/tun"
    warn "Or deploy to a platform with full container support."
    echo "skipped (no-capabilities)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  if ! install_cli; then
    echo "failed (install)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  if ! init_cli; then
    echo "failed (init)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  # Initial connection (with retry)
  local max_attempts=3
  local attempt=1
  while [ $attempt -le $max_attempts ]; do
    log "Connection attempt ${attempt}/${max_attempts}..."
    if connect; then
      break
    fi
    attempt=$((attempt + 1))
    [ $attempt -le $max_attempts ] && sleep 10
  done

  if [ $attempt -gt $max_attempts ]; then
    err "Failed to connect after ${max_attempts} attempts."
    echo "failed (connect)" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi

  # Rotation loop
  local interval_seconds=$((PROTONVPN_ROTATE_INTERVAL * 60))
  log "Rotation loop started: every ${PROTONVPN_ROTATE_INTERVAL} min."

  while true; do
    sleep "$interval_seconds"
    rotate
  done
}

# ── CLI dispatch ──
case "${1:-service}" in
  service)    run_service ;;
  connect)    install_cli; init_cli; connect ;;
  disconnect) disconnect ;;
  rotate)     rotate ;;
  status)
    if [ -f "$STATUS_FILE" ]; then
      cat "$STATUS_FILE"
    else
      echo "unknown"
    fi
    if command -v protonvpn &>/dev/null; then
      echo "---"
      protonvpn status 2>&1 || echo "CLI status unavailable"
    fi
    ;;
  install)    install_cli ;;
  check)      check_capabilities && echo "capabilities: ok" || echo "capabilities: missing" ;;
  *)
    echo "Usage: $0 {service|connect|disconnect|rotate|status|install|check}"
    exit 1
    ;;
esac
