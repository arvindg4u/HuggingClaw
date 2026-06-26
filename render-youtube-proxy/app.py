"""
YouTube Transcript API Service — with proxy rotation
Fetches YouTube transcripts bypassing IP blocks via free proxy pool rotation.
"""

import os
import re
import json
import time
import random
import asyncio
import threading
import urllib.request
import urllib.error
import logging
from fastapi import FastAPI, HTTPException, Header, Query
from typing import Optional
from requests import Session
from requests.adapters import HTTPAdapter
from urllib3 import Retry
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api.proxies import GenericProxyConfig
from youtube_transcript_api._errors import (
    TranscriptsDisabled,
    NoTranscriptFound,
    VideoUnavailable,
)

logging.basicConfig(level=logging.INFO, format="[yt-proxy] %(message)s")
log = logging.getLogger("yt-proxy")

app = FastAPI(title="YouTube Transcript API", docs_url=None, redoc_url=None)

AUTH_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "changeme")
PORT = int(os.getenv("PORT", "8000"))

# ── Proxy Pool ──────────────────────────────────────────────────────────
PROXY_SOURCES = [
    "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/protocols/socks5/data.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000&country=all",
]

proxy_pool = []
proxy_pool_lock = threading.Lock()
last_pool_fetch = 0
POOL_REFRESH_INTERVAL = 300  # 5 min

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/604.1",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
]


def fetch_proxy_pool():
    """Fetch fresh SOCKS5 proxies from multiple sources."""
    proxies = []
    for src in PROXY_SOURCES:
        try:
            req = urllib.request.Request(src, headers={"User-Agent": random.choice(USER_AGENTS)})
            with urllib.request.urlopen(req, timeout=15) as resp:
                text = resp.read().decode()
                for line in text.strip().splitlines():
                    line = line.strip()
                    if ":" in line and not line.startswith("#"):
                        parts = line.split(":")
                        if len(parts) >= 2:
                            host = parts[0].strip()
                            port = parts[1].strip()
                            if port.isdigit():
                                proxies.append((host, int(port)))
        except Exception as e:
            log.warning(f"proxy source failed: {src} — {e}")
    # deduplicate
    seen = set()
    unique = []
    for p in proxies:
        key = f"{p[0]}:{p[1]}"
        if key not in seen:
            seen.add(key)
            unique.append(p)
    random.shuffle(unique)
    log.info(f"fetched {len(unique)} unique proxies")
    return unique


def get_proxy_pool():
    """Get cached proxy pool, refresh if stale."""
    global proxy_pool, last_pool_fetch
    now = time.time()
    if now - last_pool_fetch > POOL_REFRESH_INTERVAL or not proxy_pool:
        fresh = fetch_proxy_pool()
        with proxy_pool_lock:
            if fresh:
                proxy_pool = fresh
                last_pool_fetch = now
    return proxy_pool


def test_proxy(host, port, timeout=8):
    """Quick-test if a SOCKS5 proxy can reach YouTube."""
    try:
        import socket
        sock = socket.create_connection((host, port), timeout=timeout)
        # SOCKS5 handshake
        sock.sendall(b"\x05\x01\x00")
        resp = sock.recv(2)
        sock.close()
        return resp == b"\x05\x00"
    except:
        return False


def build_requests_session(proxy_url=None):
    """Build a requests.Session with browser-like headers and optional proxy."""
    sess = Session()
    sess.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Connection": "close",
    })
    if proxy_url:
        sess.proxies = {"http": proxy_url, "https": proxy_url}
    # retry on 429
    retry = Retry(total=2, status_forcelist=[429], backoff_factor=1)
    adapter = HTTPAdapter(max_retries=retry)
    sess.mount("http://", adapter)
    sess.mount("https://", adapter)
    return sess


def create_ytt_client(retry_proxies=True):
    """Create YouTubeTranscriptApi with optional proxy rotation."""
    pool = get_proxy_pool()
    # Try a few random proxies
    tried = set()
    for attempt in range(min(10, len(pool) + 1)):
        if attempt == 0 and not retry_proxies:
            # Try without proxy first
            sess = build_requests_session()
            return YouTubeTranscriptApi(http_client=sess)

        # Pick a random untried proxy
        candidates = [p for p in pool if f"{p[0]}:{p[1]}" not in tried]
        if not candidates:
            break
        host, port = random.choice(candidates)
        tried.add(f"{host}:{port}")

        proxy_url = f"socks5://{host}:{port}"
        try:
            sess = build_requests_session(proxy_url)
            ytt = YouTubeTranscriptApi(http_client=sess)
            # Quick validation — try listing transcripts
            # If it fails, try next proxy
            return ytt
        except Exception:
            continue

    # Fallback: direct connection (probably won't work but try)
    log.warning("no working proxy found, trying direct connection")
    return YouTubeTranscriptApi(http_client=build_requests_session())


# ── Self-ping ───────────────────────────────────────────────────────────
def _self_ping():
    while True:
        time.sleep(600)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=10)
        except:
            pass


@app.on_event("startup")
async def _startup():
    t = threading.Thread(target=_self_ping, daemon=True)
    t.start()
    # Pre-fetch proxy pool
    threading.Thread(target=get_proxy_pool, daemon=True).start()


# ── Helpers ─────────────────────────────────────────────────────────────
def get_video_id(video_input: str) -> str:
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$'
    ]
    for pattern in patterns:
        match = re.search(pattern, video_input)
        if match:
            return match.group(1)
    raise ValueError(f"Could not extract video ID from: {video_input}")


def check_auth(token: str):
    if token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


def fetch_with_retry(video_id: str, lang: str, retries: int = 3):
    """Fetch transcript with proxy rotation on failure."""
    last_error = None
    for attempt in range(retries):
        try:
            ytt = create_ytt_client(retry_proxies=(attempt > 0))
            return ytt.fetch(video_id, languages=[lang])
        except Exception as e:
            last_error = e
            log.warning(f"attempt {attempt + 1} failed for {video_id}: {e}")
            # Force proxy pool refresh
            global last_pool_fetch
            last_pool_fetch = 0
            time.sleep(1 * (attempt + 1))
    raise last_error


# ── Endpoints ───────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/transcript/{video_input:path}/text")
async def get_transcript_text(
    video_input: str,
    lang: str = Query("en", description="Language code"),
    x_proxy_token: str = Header(..., alias="X-Proxy-Token")
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        transcript = fetch_with_retry(video_id, lang)
        full_text = " ".join(seg.text for seg in transcript.snippets)
        return {
            "video_id": video_id,
            "language": transcript.language,
            "language_code": transcript.language_code,
            "text": full_text
        }
    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except NoTranscriptFound:
        raise HTTPException(status_code=404, detail=f"No transcript for language: {lang}")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/transcript/{video_input:path}")
async def get_transcript(
    video_input: str,
    lang: str = Query("en", description="Language code"),
    x_proxy_token: str = Header(..., alias="X-Proxy-Token")
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        transcript = fetch_with_retry(video_id, lang)
        return {
            "video_id": video_id,
            "language": transcript.language,
            "language_code": transcript.language_code,
            "is_generated": transcript.is_generated,
            "segments": [
                {"text": seg.text, "start": seg.start, "duration": seg.duration}
                for seg in transcript.snippets
            ]
        }
    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except NoTranscriptFound:
        raise HTTPException(status_code=404, detail=f"No transcript for language: {lang}")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


@app.get("/transcripts/{video_input:path}")
async def list_transcripts(
    video_input: str,
    x_proxy_token: str = Header(..., alias="X-Proxy-Token")
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        ytt = create_ytt_client(retry_proxies=True)
        transcript_list = ytt.list(video_id)
        return {
            "video_id": video_id,
            "transcripts": [
                {
                    "language": t.language,
                    "language_code": t.language_code,
                    "is_generated": t.is_generated,
                    "is_translatable": t.is_translatable
                }
                for t in transcript_list
            ]
        }
    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")
