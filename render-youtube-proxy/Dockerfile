# Stage 1: Build bgutil-ytdlp-pot-provider server (Node.js only)
FROM node:22-bookworm-slim AS bgutil-build

WORKDIR /bgutil
ADD https://github.com/Brainicism/bgutil-ytdlp-pot-provider/archive/master.tar.gz /tmp/src.tar.gz
RUN tar xzf /tmp/src.tar.gz --strip-components=1 && \
    cd server && npm ci && npx tsc

# Stage 2: Final image — Node.js (built-in) + Python + yt-dlp + PO Tokens
FROM node:22-bookworm-slim

WORKDIR /app

# ── Install Python 3 + pip ────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-venv && \
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

# ── Copy the FastAPI app ──────────────────────────────────────────
COPY app.py .

EXPOSE 8000

# ── Start bgutil PO token server (background) + FastAPI ──────────
CMD ["sh", "-c", \
  "node /opt/bgutil/build/main.js --port 4416 & \
   sleep 1 && \
   python3 -m uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
