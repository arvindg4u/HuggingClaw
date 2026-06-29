#!/usr/bin/env python3
"""
YouTube Transcript API Service — yt-dlp + WireGuard VPN tunnel.
All traffic routes through the WireGuard tunnel via HTTP CONNECT proxy
to bypass YouTube IP blocks from cloud providers (Render, etc.).
"""

import os
import re
import subprocess
import json
import tempfile
import shutil
import urllib.request
import urllib.error
from pathlib import Path
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="YouTube Transcript API", docs_url=None, redoc_url=None)

AUTH_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "changeme")
PORT = int(os.getenv("PORT", "8000"))

# yt-dlp player clients to try (android first)
PLAYER_CLIENTS = ["android", "tv", "ios", "web", "mweb"]

# bgutil PO token server runs on localhost:4416
BGUTIL_URL = "http://127.0.0.1:4416"
BGUTIL_EXARGS = f"youtubepot-bgutilhttp:base_url={BGUTIL_URL}"

# ── WireGuard Tunnel (wireproxy HTTP CONNECT proxy) ────────────────
TUNNEL_HOST = "127.0.0.1"
TUNNEL_PORT = int(os.getenv("WG_TUNNEL_PORT", "25345"))
TUNNEL_STATUS_FILE = "/tmp/wireguard/status"
TUNNEL_PROXY = f"http://{TUNNEL_HOST}:{TUNNEL_PORT}"


def is_tunnel_available() -> bool:
    """Check if WireGuard tunnel is active via status file + port check."""
    try:
        st = Path(TUNNEL_STATUS_FILE).read_text().strip()
        if st != "connected":
            return False
        data = Path("/proc/net/tcp").read_text()
        hex_port = format(TUNNEL_PORT, "x").lower()
        for line in data.split("\n"):
            parts = line.strip().split()
            if len(parts) >= 4:
                addr_part = parts[1]
                state = parts[3]
                ci = addr_part.find(":")
                if ci >= 0 and addr_part[ci + 1:].lower() == hex_port and state == "0A":
                    return True
        return False
    except (OSError, IOError):
        return False


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
    """Extract plain text from VTT subtitle content.
    Deduplicates consecutive identical lines (auto-generated captions
    often repeat each cue 3 times due to overlapping language variants)."""
    lines = []
    prev = None
    for line in text.split("\n"):
        line = line.strip()
        if not line or line.startswith("WEBVTT") or line.startswith("Kind:") or line.startswith("Language:") or "-->" in line or line.isdigit():
            continue
        line = re.sub(r'<[^>]+>', '', line)
        line = line.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if line and line != prev:
            lines.append(line)
            prev = line
    return " ".join(lines)


def fetch_transcript(video_id: str, lang: str = "en") -> dict:
    """Fetch transcript through the WireGuard tunnel using HTTP CONNECT proxy."""
    if not is_tunnel_available():
        raise HTTPException(status_code=502, detail="WireGuard tunnel not available")

    proxy_url = TUNNEL_PROXY
    url = f"https://www.youtube.com/watch?v={video_id}"

    for client in PLAYER_CLIENTS:
        tmpdir = tempfile.mkdtemp()
        try:
            exargs = f"youtube:player_client={client},{BGUTIL_EXARGS}"
            result = subprocess.run(
                [
                    "yt-dlp",
                    "--proxy", proxy_url,
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
                capture_output=True, text=True, timeout=90,
            )

            for fname in os.listdir(tmpdir):
                if fname.endswith(".vtt"):
                    with open(os.path.join(tmpdir, fname), "r", encoding="utf-8") as fp:
                        vtt = fp.read()
                    text = parse_vtt(vtt)
                    if text.strip():
                        return {"text": text, "client": client, "video_id": video_id}

        except subprocess.TimeoutExpired:
            continue
        except Exception:
            continue
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    raise HTTPException(status_code=502, detail="YouTube blocked all clients through tunnel")


def fetch_info(video_id: str) -> dict:
    """Get video info via yt-dlp through the WireGuard tunnel."""
    if not is_tunnel_available():
        return {"title": "", "transcripts": []}

    url = f"https://www.youtube.com/watch?v={video_id}"
    for client in PLAYER_CLIENTS[:3]:
        try:
            exargs = f"youtube:player_client={client},{BGUTIL_EXARGS}"
            result = subprocess.run(
                ["yt-dlp", "--proxy", TUNNEL_PROXY, "--skip-download", "--dump-json",
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
        raise HTTPException(status_code=403, detail="Invalid auth token")


# ── Health / Tunnel Status ─────────────────────────────────────────

def get_tunnel_status() -> dict:
    """Get WireGuard tunnel status."""
    available = is_tunnel_available()
    status = {"available": available, "proxy": TUNNEL_PROXY if available else None}
    try:
        ip_file = Path("/tmp/wireguard/exit_ip")
        if ip_file.exists():
            status["exit_ip"] = ip_file.read_text().strip()
    except OSError:
        pass
    try:
        st_file = Path(TUNNEL_STATUS_FILE)
        if st_file.exists():
            status["wg_status"] = st_file.read_text().strip()
    except OSError:
        pass
    return status


@app.get("/health")
async def health():
    tunnel = get_tunnel_status()
    return {
        "status": "ok",
        "tunnel": tunnel,
        "po_tokens": True,
        "player_clients": PLAYER_CLIENTS,
    }


@app.get("/tunnel")
async def tunnel_status():
    """Get WireGuard VPN tunnel status."""
    return get_tunnel_status()


# ── REST Endpoints ─────────────────────────────────────────────────

@app.get("/transcript/{video_input}")
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


@app.get("/transcript/{video_input}/text")
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
    return {"video_id": video_id, "language": lang, "client": data["client"], "text": data["text"]}


@app.get("/transcripts/{video_input}")
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
