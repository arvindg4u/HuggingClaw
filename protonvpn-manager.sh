#!/bin/bash
# ════════════════════════════════════════════════════════════════
# 🛡️  Proton VPN Manager — Benign privacy layer for outbound API
#     traffic. Encrypts the app's HTTP/HTTPS requests to LLM
#     providers. Does NOT bypass HuggingFace Spaces restrictions
#     or route user traffic.
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
PROTONVPN_TIER="${PROTONVPN_TIER:-2}"       # 0=Free, 1=Basic, 2=Plus, 3=Visionary
PROTONVPN_ROTATE_INTERVAL="${PROTONVPN_ROTATE_INTERVAL:-30}"  # minutes
PROTONVPN_COUNTRY="${PROTONVPN_COUNTRY:-}"  # optional: US, NL, JP, etc.
PROTONVPN_PROTOCOL="${PROTONVPN_PROTOCOL:-udp}"  # udp or tcp

STATE_DIR="/home/node/.protonvpn"
PID_FILE="${STATE_DIR}/pid"
STATUS_FILE="${STATE_DIR}/status"
LOG_FILE="${STATE_DIR}/manager.log"

# ── Helper: check capabilities ──
check_capabilities() {
  # Check if we have NET_ADMIN capability (needed for VPN tunnel)
  if ! ip link show lo &>/dev/null 2>&1; then
    warn "Network interfaces not accessible — VPN may not work in this environment."
    return 1
  fi
  # Check if tun module is available
  if [ ! -e /dev/net/tun ] && ! lsmod 2>/dev/null | grep -q tun; then
    warn "/dev/net/tun not found — attempting to create..."
    mkdir -p /dev/net 2>/dev/null || true
    mknod /dev/net/tun c 10 200 2>/dev/null || true
  fi
  if [ -e /dev/net/tun ]; then
    return 0
  else
    warn "TUN device not available — VPN may not work."
    return 1
  fi
}

# ── Install community CLI (if missing) ──
install_cli() {
  if command -v protonvpn &>/dev/null; then
    log "Proton VPN CLI already installed."
    return 0
  fi
  log "Installing Proton VPN Community CLI (headless-compatible)..."
  pip3 install --no-cache-dir --break-system-packages \
    "git+https://github.com/jonasjancarik/protonvpn-cli-community.git@latest" 2>&1 | tail -5
  if command -v protonvpn &>/dev/null; then
    log "Proton VPN CLI installed successfully."
  else
    err "Failed to install Proton VPN CLI."
    return 1
  fi
}

# ── Initialize CLI with credentials ──
init_cli() {
  if [ -z "$PROTONVPN_USERNAME" ] || [ -z "$PROTONVPN_PASSWORD" ]; then
    err "PROTONVPN_USERNAME and PROTONVPN_PASSWORD must be set."
    return 1
  fi

  log "Initializing Proton VPN with tier ${PROTONVPN_TIER}..."

  # The community CLI stores credentials in its config
  # Use init with credentials via stdin
  printf '%s\n' "$PROTONVPN_USERNAME" "$PROTONVPN_PASSWORD" | \
    protonvpn init --tier "${PROTONVPN_TIER}" --protocol "${PROTONVPN_PROTOCOL}" 2>&1 || true

  # If init was already done, configure tier
  protonvpn configure --tier "${PROTONVPN_TIER}" 2>/dev/null || true
  protonvpn configure --protocol "${PROTONVPN_PROTOCOL}" 2>/dev/null || true

  log "Proton VPN initialized."
}

# ── Connect to VPN ──
connect() {
  log "Connecting to Proton VPN..."

  # Disconnect any existing session first
  protonvpn disconnect 2>/dev/null || true
  sleep 2

  if [ -n "$PROTONVPN_COUNTRY" ]; then
    log "Connecting to fastest server in: ${PROTONVPN_COUNTRY}"
    protonvpn connect --cc "$PROTONVPN_COUNTRY" 2>&1 | tail -3
  else
    log "Connecting to fastest available server..."
    protonvpn connect --fastest 2>&1 | tail -3
  fi

  # Verify connection
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
    err "VPN connection failed. Status: ${status}"
    echo "disconnected" > "$STATUS_FILE"
    chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
    return 1
  fi
}

# ── Disconnect ──
disconnect() {
  log "Disconnecting Proton VPN..."
  protonvpn disconnect 2>&1 | tail -2 || true
  echo "disconnected" > "$STATUS_FILE"
  chown 1000:1000 "$STATUS_FILE" 2>/dev/null || true
  sleep 2
}

# ── Rotate server (disconnect + reconnect) ──
rotate() {
  log "Rotating VPN server..."
  local old_ip
  old_ip=$(cat "${STATE_DIR}/last_ip" 2>/dev/null || echo "unknown")
  disconnect
  sleep 3
  connect
  local new_ip
  new_ip=$(cat "${STATE_DIR}/last_ip" 2>/dev/null || echo "unknown")
  if [ "$old_ip" != "$new_ip" ] && [ "$new_ip" != "unknown" ]; then
    log "IP rotated: ${old_ip} → ${new_ip}"
  elif [ "$old_ip" = "$new_ip" ]; then
    warn "IP did not change after rotation — may be on same server."
  fi
}

# ── Main loop: connect and rotate ──
run_service() {
  mkdir -p "$STATE_DIR"
  # Ensure node user can read status (we run via sudo as root)
  chown -R 1000:1000 "$STATE_DIR" 2>/dev/null || true

  if ! check_capabilities; then
    warn "VPN capability check failed. Running in degraded mode (no VPN)."
    echo "degraded" > "$STATUS_FILE"
    return 1
  fi

  if ! install_cli; then
    err "CLI installation failed."
    echo "failed" > "$STATUS_FILE"
    return 1
  fi

  if ! init_cli; then
    err "CLI initialization failed."
    echo "failed" > "$STATUS_FILE"
    return 1
  fi

  # Initial connection
  if ! connect; then
    warn "Initial connection failed — will retry in 60s..."
    echo "retrying" > "$STATUS_FILE"
    sleep 60
    connect || true
  fi

  # Rotation loop
  local interval_seconds=$((PROTONVPN_ROTATE_INTERVAL * 60))
  log "Starting rotation loop: every ${PROTONVPN_ROTATE_INTERVAL} minutes."

  while true; do
    log "Next rotation in ${PROTONVPN_ROTATE_INTERVAL} minutes..."
    sleep "$interval_seconds"
    rotate
  done
}

# ── Command dispatch ──
case "${1:-service}" in
  service)
    run_service
    ;;
  connect)
    install_cli
    init_cli
    connect
    ;;
  disconnect)
    disconnect
    ;;
  rotate)
    rotate
    ;;
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
  install)
    install_cli
    ;;
  *)
    echo "Usage: $0 {service|connect|disconnect|rotate|status|install}"
    exit 1
    ;;
esac
