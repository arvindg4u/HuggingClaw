# Stage 1: Build bgutil-ytdlp-pot-provider server (Node.js)
FROM node:25-bookworm-slim AS bgutil-build

WORKDIR /bgutil
RUN apt-get update && apt-get install -y git && \
    git clone --depth 1 --branch v1.3.1 https://github.com/Brainicism/bgutil-ytdlp-pot-provider.git . && \
    cd server && npm ci && npx tsc

# Stage 2: Final image — Python + Node.js + yt-dlp + PO Tokens
FROM python:3.12-slim

WORKDIR /app

# ── Install Node.js 20+ (for bgutil PO token server) ──────────────
RUN apt-get update && apt-get install -y curl gnupg && \
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# ── Install Python dependencies (yt-dlp, bgutil plugin, FastAPI) ──
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

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
   uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
