#!/usr/bin/env python3
"""
YouTube Transcript API Service — yt-dlp + PO Tokens via bgutil-ytdlp-pot-provider.
Now with PO Token support to bypass YouTube IP blocks from cloud providers.
"""

import os
import re
import subprocess
import json
import tempfile
import shutil
import threading
import time
import urllib.request
import urllib.error
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="YouTube Transcript API", docs_url=None, redoc_url=None)

AUTH_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "changeme")
PORT = int(os.getenv("PORT", "8000"))

# yt-dlp player clients to try (android first — works best with PO tokens)
PLAYER_CLIENTS = ["android", "tv", "ios", "web", "mweb"]

# bgutil PO token server runs on localhost:4416
BGUTIL_URL = "http://127.0.0.1:4416"
# Extractor args passed to yt-dlp for PO token support
BGUTIL_EXARGS = f"youtubepot-bgutilhttp:base_url={BGUTIL_URL}"


def get_video_id(video_input: str) -> str:
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$'
    ]
    for p in patterns:
        m = re.search(p, video_input)
        if m:
            return m.group(1)
    raise ValueError(f"Invalid video input: {video_input}")


def parse_vtt(text: str) -> str:
    """Extract plain text from VTT subtitle content."""
    lines = []
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("WEBVTT") or line.startswith("Kind:") or line.startswith("Language:") or "-->" in line or line.isdigit():
            continue
        line = re.sub(r'<[^>]+>', '', line)
        line = line.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if line:
            lines.append(line)
    return " ".join(lines)


def fetch_transcript(video_id: str, lang: str = "en") -> dict:
    """Fetch transcript via yt-dlp with PO token support, trying multiple player clients."""
    url = f"https://www.youtube.com/watch?v={video_id}"

    for client in PLAYER_CLIENTS:
        tmpdir = tempfile.mkdtemp()
        try:
            exargs = f"youtube:player_client={client},{BGUTIL_EXARGS}"
            result = subprocess.run(
                [
                    "yt-dlp",
                    "--skip-download",
                    "--write-auto-sub", "--write-subs",
                    "--sub-langs", f"{lang},en",
                    "--sub-format", "vtt",
                    "--convert-subs", "vtt",
                    "--extractor-args", exargs,
                    "--output", os.path.join(tmpdir, "%(id)s"),
                    "--no-warnings", "--quiet",
                    url,
                ],
                capture_output=True, text=True, timeout=60,
            )

            if result.returncode != 0:
                stderr = result.stderr.strip()
                if "block" in stderr.lower() or "429" in stderr or "403" in stderr:
                    continue  # Try next client

            for fname in os.listdir(tmpdir):
                if fname.endswith(".vtt"):
                    with open(os.path.join(tmpdir, fname), "r", encoding="utf-8") as fp:
                        vtt = fp.read()
                    text = parse_vtt(vtt)
                    if text.strip():
                        return {"text": text, "client": client, "video_id": video_id}

        except subprocess.TimeoutExpired:
            pass
        except Exception:
            pass
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    raise HTTPException(status_code=502, detail="YouTube blocked all clients")


def fetch_info(video_id: str) -> dict:
    """Get video info via yt-dlp with PO token support."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    for client in PLAYER_CLIENTS[:3]:
        try:
            exargs = f"youtube:player_client={client},{BGUTIL_EXARGS}"
            result = subprocess.run(
                ["yt-dlp", "--skip-download", "--dump-json",
                 "--extractor-args", exargs,
                 "--no-warnings", "--quiet", url],
                capture_output=True, text=True, timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                subs = {**data.get("subtitles", {}), **data.get("automatic_captions", {})}
                return {
                    "title": data.get("title", ""),
                    "duration": data.get("duration", 0),
                    "channel": data.get("channel", ""),
                    "view_count": data.get("view_count", 0),
                    "like_count": data.get("like_count", 0),
                    "transcripts": list(subs.keys()),
                }
        except Exception:
            continue
    return {"title": "", "transcripts": []}


def check_auth(token: str):
    if AUTH_TOKEN and token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


def _bgutil_health() -> bool:
    """Check if bgutil PO token server is reachable."""
    try:
        urllib.request.urlopen(f"{BGUTIL_URL}/ping", timeout=3)
        return True
    except Exception:
        return False


# ── Self-ping & health ──────────────────────────────────────────────
def _self_ping():
    while True:
        time.sleep(600)
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{PORT}/health", timeout=10)
        except:
            pass


@app.on_event("startup")
async def _startup():
    threading.Thread(target=_self_ping, daemon=True).start()
    if _bgutil_health():
        print("[yt-proxy] bgutil PO token server is RUNNING on localhost:4416")
    else:
        print("[yt-proxy] WARNING: bgutil PO token server NOT reachable")


# ── REST Endpoints ──────────────────────────────────────────────────
@app.get("/health")
async def health():
    bgutil_ok = _bgutil_health()
    return {
        "status": "ok",
        "engine": "yt-dlp",
        "po_tokens": bgutil_ok,
        "clients": PLAYER_CLIENTS,
    }


@app.get("/transcript/{video_input:path}/text")
async def get_transcript_text(
    video_input: str,
    lang: str = Query("en"),
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    data = fetch_transcript(video_id, lang)
    return {
        "video_id": video_id,
        "language": lang,
        "client": data["client"],
        "text": data["text"],
    }


@app.get("/transcript/{video_input:path}")
async def get_transcript(
    video_input: str,
    lang: str = Query("en"),
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    data = fetch_transcript(video_id, lang)
    segments = [{"text": s, "start": 0, "duration": 0} for s in data["text"].split(". ")]
    return {
        "video_id": video_id,
        "language": lang,
        "client": data["client"],
        "is_generated": True,
        "segments": segments,
    }


@app.get("/transcripts/{video_input:path}")
async def list_transcripts(
    video_input: str,
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_auth(x_proxy_token)
    try:
        video_id = get_video_id(video_input)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    info = fetch_info(video_id)
    return {
        "video_id": video_id,
        "source": "yt-dlp",
        "transcripts": [{"language": t, "language_code": t} for t in info.get("transcripts", [])],
    }


# ── MCP Endpoint ────────────────────────────────────────────────────

MCP_TOOLS = [
    {"name": "get_transcript", "description": "Get YouTube video transcript with timestamps",
     "inputSchema": {"type": "object", "properties": {
         "videoId": {"type": "string", "description": "YouTube video ID or URL"},
         "lang": {"type": "string", "description": "Language code", "default": "en"},
     }, "required": ["videoId"]}},
    {"name": "get_transcript_text", "description": "Get YouTube video transcript as plain text",
     "inputSchema": {"type": "object", "properties": {
         "videoId": {"type": "string", "description": "YouTube video ID or URL"},
         "lang": {"type": "string", "description": "Language code", "default": "en"},
     }, "required": ["videoId"]}},
    {"name": "list_transcripts", "description": "List available transcript languages",
     "inputSchema": {"type": "object", "properties": {
         "videoId": {"type": "string", "description": "YouTube video ID or URL"},
     }, "required": ["videoId"]}},
]


@app.post("/mcp")
async def mcp_handler(request: Request):
    body = await request.json()
    rid = body.get("id")
    method = body.get("method")
    params = body.get("params", {})
    auth = request.headers.get("x-proxy-token", "")

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"tools": MCP_TOOLS}})

    if method == "tools/call":
        tool = params.get("name", "")
        args = params.get("arguments", {})
        if AUTH_TOKEN and auth != AUTH_TOKEN:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": "Unauthorized"}})
        try:
            vid = get_video_id(args.get("videoId", ""))
            lang = args.get("lang", "en")
        except ValueError as e:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}})

        try:
            if tool in ("get_transcript_text", "get_transcript"):
                data = fetch_transcript(vid, lang)
                text = data["text"]
                if tool == "get_transcript":
                    lines = [f"[{i}] {s}" for i, s in enumerate(text.split(". "), 1)]
                    text = "Transcript:\n" + "\n".join(lines)
                return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}})

            if tool == "list_transcripts":
                info = fetch_info(vid)
                tracks = info.get("transcripts", [])
                lines = [f"  - {t}" for t in tracks]
                text = "Available transcripts:\n" + "\n".join(lines)
                return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}})
        except HTTPException as e:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": e.detail}})
        except Exception as e:
            return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}})

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "youtube-transcript", "version": "1.0.0"},
            "capabilities": {"tools": {}},
        }})
    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": rid, "result": {}})
    return JSONResponse({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown method: {method}"}})
