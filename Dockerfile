# ════════════════════════════════════════════════════════════════
# 🦞 HuggingClaw + 💻 JupyterLab Terminal
# ════════════════════════════════════════════════════════════════
# Port 7861 (exposed): Dashboard + reverse proxy
#   /          → HuggingClaw dashboard
#   /app/      → OpenClaw gateway (internal :7860)
#   /terminal/ → JupyterLab terminal (internal :8888)
#
# Optional Proton VPN for outbound traffic encryption (opt-in via env vars).
# ════════════════════════════════════════════════════════════════

# ── Stage 1: Pull pre-built OpenClaw ──
ARG OPENCLAW_VERSION=latest
FROM ghcr.io/openclaw/openclaw:${OPENCLAW_VERSION} AS openclaw

# ── Stage 2: Runtime ──
FROM node:22-slim
ARG OPENCLAW_VERSION=latest
ARG DEV_MODE=false

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    sudo \
    file \
    ca-certificates \
    jq \
    curl \
    dbus \
    dbus-x11 \
    python3 \
    python3-pip \
    chromium \
    libnss3 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libdrm2 \
    libgbm1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxkbcommon0 \
    libx11-6 \
    libxext6 \
    libxfixes3 \
    libasound2 \
    fonts-dejavu-core \
    fonts-liberation \
    fonts-noto-color-emoji \
    fonts-freefont-ttf \
    fonts-ipafont-gothic \
    fonts-wqy-zenhei \
    xfonts-scalable \
    --no-install-recommends && \
    pip3 install --no-cache-dir --break-system-packages \
      huggingface_hub hf_transfer && \
    rm -rf /var/lib/apt/lists/*

# ── Install wireproxy (userspace WireGuard → HTTP CONNECT, no TUN needed) ──
ARG TARGETARCH
RUN set -ex && \
    arch="${TARGETARCH:-amd64}" && [ "$arch" = "arm64" ] || [ "$arch" = "amd64" ] || arch="amd64" && \
    url="https://github.com/octeep/wireproxy/releases/latest/download/wireproxy_linux_${arch}.tar.gz" && \
    echo "Downloading wireproxy from ${url}..." && \
    curl -fsSL --max-time 60 "$url" -o /tmp/wireproxy.tar.gz && \
    tar -xzf /tmp/wireproxy.tar.gz -C /tmp/ && \
    mv /tmp/wireproxy /usr/local/bin/wireproxy && \
    chmod +x /usr/local/bin/wireproxy && \
    rm -f /tmp/wireproxy.tar.gz && \
    wireproxy --version 2>&1 | head -1 && \
    echo "wireproxy installed successfully." 

RUN if [ "${DEV_MODE}" = "true" ] || [ "${DEV_MODE}" = "1" ] || [ "${DEV_MODE}" = "yes" ] || [ "${DEV_MODE}" = "on" ]; then \
      pip3 install --no-cache-dir --break-system-packages \
        jupyterlab==4.5.7 \
        tornado==6.5.5 \
        ipywidgets==8.1.8 && \
      python3 -c "from pathlib import Path; import shutil, jupyter_server; d=Path(jupyter_server.__file__).parent/'templates'; d.mkdir(parents=True,exist_ok=True); shutil.copyfile('/home/node/app/login.html', d/'login.html')" || true; \
    fi

RUN mkdir -p /home/node/app /home/node/.openclaw && \
    chown -R 1000:1000 /home/node && \
    printf '%s\n' \
      'Cmnd_Alias HUGGINGCLAW_APT = /usr/bin/apt, /usr/bin/apt-get, /usr/bin/dpkg' \
      'node ALL=(root) NOPASSWD: HUGGINGCLAW_APT' \
      > /etc/sudoers.d/huggingclaw-apt && \
    chmod 0440 /etc/sudoers.d/huggingclaw-apt && \
    visudo -cf /etc/sudoers.d/huggingclaw-apt

COPY --from=openclaw --chown=1000:1000 /app /home/node/.openclaw/openclaw-app

RUN mkdir -p /home/node/browser-deps && \
    cd /home/node/browser-deps && \
    npm init -y && \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 npm install --omit=dev playwright@1.59.1 ws@8.18.3

RUN ln -s /home/node/.openclaw/openclaw-app/openclaw.mjs /usr/local/bin/openclaw 2>/dev/null || \
    npm install -g openclaw@${OPENCLAW_VERSION}

# ── Pre-bundle WhatsApp plugin (build time, real directory) ──
RUN mkdir -p /home/node/.openclaw/extensions && \
    if HOME=/home/node openclaw plugins install clawhub:@openclaw/whatsapp 2>/dev/null; then \
      echo "[build] WhatsApp plugin pre-bundled from ClawHub."; \
    elif HOME=/home/node openclaw plugins install @openclaw/whatsapp 2>/dev/null; then \
      echo "[build] WhatsApp plugin pre-bundled from npm."; \
    else \
      echo "[build] Warning: could not pre-bundle WhatsApp plugin (will install at runtime)"; \
    fi && \
    chown -R 1000:1000 /home/node/.openclaw

COPY --chown=1000:1000 cloudflare-proxy.js /opt/cloudflare-proxy.js
COPY --chown=1000:1000 dns-resolve.py /home/node/app/dns-resolve.py
COPY --chown=1000:1000 health-server.js /home/node/app/health-server.js
COPY --chown=1000:1000 login.html /home/node/app/login.html
COPY --chown=1000:1000 iframe-fix.cjs /home/node/app/iframe-fix.cjs
COPY --chown=1000:1000 start.sh /home/node/app/start.sh
COPY --chown=1000:1000 wa-guardian.js /home/node/app/wa-guardian.js
COPY --chown=1000:1000 package-manifest.sh /home/node/app/package-manifest.sh
COPY --chown=1000:1000 openclaw-sync.py /home/node/app/openclaw-sync.py
COPY --chown=1000:1000 env-builder.html /home/node/app/env-builder.html
COPY --chown=1000:1000 env-builder.js /home/node/app/env-builder.js
COPY --chown=1000:1000 jupyter-devdata-sync.py /home/node/app/jupyter-devdata-sync.py
COPY --chown=1000:1000 dns-fix.cjs /home/node/app/dns-fix.cjs
COPY --chown=1000:1000 telegram-proxy.cjs /home/node/app/telegram-proxy.cjs
COPY --chown=1000:1000 whatsapp-proxy.cjs /home/node/app/whatsapp-proxy.cjs
COPY --chown=1000:1000 protonvpn-manager.sh /home/node/app/protonvpn-manager.sh
RUN chmod +x /home/node/app/start.sh \
              /home/node/app/package-manifest.sh \
              /home/node/app/protonvpn-manager.sh \
              /home/node/app/openclaw-sync.py \
              /home/node/app/jupyter-devdata-sync.py \
              /home/node/app/dns-resolve.py

# ── Fix /tmp ownership (Docker build as root leaves root-owned files) ──
RUN chown -R 1000:1000 /tmp/

USER node

ENV HOME=/home/node \
    OPENCLAW_VERSION=${OPENCLAW_VERSION} \
    PATH=/home/node/.local/bin:/usr/local/bin:$PATH \
    OPENCLAW_TEMP_DIR=/home/node/.openclaw/tmp \
    NODE_PATH=/home/node/browser-deps/node_modules \
    NODE_OPTIONS="--require /home/node/app/dns-fix.cjs --require /opt/cloudflare-proxy.js --require /home/node/app/telegram-proxy.cjs --require /home/node/app/whatsapp-proxy.cjs"

WORKDIR /home/node/app

EXPOSE 7861

HEALTHCHECK --interval=30s --timeout=5s --start-period=90s \
  CMD curl -fsS --noproxy '*' http://localhost:7861/health || exit 1

CMD ["/home/node/app/start.sh"]
