# Stage 1: Build bgutil-ytdlp-pot-provider server (Node.js only)
FROM node:22-bookworm-slim AS bgutil-build

WORKDIR /bgutil
ADD https://github.com/Brainicism/bgutil-ytdlp-pot-provider/archive/master.tar.gz /tmp/src.tar.gz
RUN tar xzf /tmp/src.tar.gz --strip-components=1 && \
    cd server && npm ci && npx tsc

# Stage 2: Final image — Node.js (built-in) + Python + yt-dlp + PO Tokens + WireGuard VPN
FROM node:22-bookworm-slim

WORKDIR /app

# ── Install Python 3 + pip + curl (for wireproxy download) ───────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv curl && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Install Python dependencies (yt-dlp, bgutil plugin, FastAPI) ──
COPY requirements.txt .
RUN PIP_BREAK_SYSTEM_PACKAGES=1 pip3 install --no-cache-dir -r requirements.txt

# ── Copy bgutil server build (compiled JS + node_modules) ─────────
COPY --from=bgutil-build /bgutil/server/build   /opt/bgutil/build
COPY --from=bgutil-build /bgutil/server/node_modules /opt/bgutil/node_modules

# ── Verify installs ────────────────────────────────────────────────
RUN yt-dlp --version && node --version && \
    python3 -c "import yt_dlp_plugins.extractor.getpot_bgutil_http; print('bgutil HTTP provider OK')"

# ── Copy the FastAPI app + WireGuard manager ─────────────────────
COPY app.py .
COPY wg-manager.sh /usr/local/bin/wg-manager.sh
RUN chmod +x /usr/local/bin/wg-manager.sh

EXPOSE 8000

# ── Start bgutil (PO tokens) + wg-manager (WireGuard VPN) + FastAPI ──
CMD ["sh", "-c", "\
node /opt/bgutil/build/main.js --port 4416 & \
wg-manager.sh & \
echo '[wg] WireGuard tunnel starting in background...' && \
echo 'Waiting for bgutil server...' && \
for i in $(seq 1 15); do \
  if curl -sf http://127.0.0.1:4416/ping > /dev/null 2>&1; then \
    echo 'bgutil ready!'; break; \
  fi; \
  echo \"attempt $i/15...\"; sleep 1; \
done && \
python3 -m uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} \
"]
