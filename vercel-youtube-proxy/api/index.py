"""
Vercel YouTube Transcript Proxy — REST API + MCP endpoint.
Zero local setup needed. Deploy to Vercel, use the URL directly.
"""

import os, re, json, random
from fastapi import FastAPI, HTTPException, Header, Query, Request
from fastapi.responses import JSONResponse
from requests import Session
from youtube_transcript_api import YouTubeTranscriptApi
from youtube_transcript_api._errors import (
    TranscriptsDisabled, NoTranscriptFound, VideoUnavailable,
)

app = FastAPI(title="YouTube Transcript API", docs_url=None, redoc_url=None)

AUTH_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "")

USER_AGENTS = [
    "com.google.android.youtube/19.09.37 (Linux; U; Android 14)",
    "com.google.android.youtube/19.08.35 (Linux; U; Android 13)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
]


def get_video_id(video_input: str) -> str:
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$',
    ]
    for p in patterns:
        m = re.search(p, video_input.strip())
        if m:
            return m.group(1)
    raise ValueError(f"Invalid video input: {video_input}")


def check_token(token: str):
    if AUTH_TOKEN and token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


def build_session():
    sess = Session()
    sess.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
    })
    return sess


def do_fetch(video_id: str, lang: str = "en"):
    """Fetch transcript and return structured data."""
    ytt = YouTubeTranscriptApi(http_client=build_session())
    transcript = ytt.fetch(video_id, languages=[lang])
    segments = [{"text": s.text, "start": s.start, "duration": s.duration} for s in transcript.snippets]
    full_text = " ".join(s["text"] for s in segments)
    return {
        "video_id": video_id,
        "language": transcript.language,
        "language_code": transcript.language_code,
        "is_generated": transcript.is_generated,
        "segments": segments,
        "text": full_text,
    }


def do_list(video_id: str):
    """List available transcripts."""
    ytt = YouTubeTranscriptApi(http_client=build_session())
    transcript_list = ytt.list(video_id)
    return {
        "video_id": video_id,
        "transcripts": [
            {"language": t.language, "language_code": t.language_code, "is_generated": t.is_generated}
            for t in transcript_list
        ],
    }


# ── REST Endpoints ─────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "engine": "youtube-transcript-api", "mcp": "/mcp"}


@app.get("/transcript/{video_id}")
@app.get("/transcript/{video_id}/text")
async def get_transcript(
    video_id: str,
    lang: str = Query("en"),
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_token(x_proxy_token)
    path = str(video_id)
    is_text = path.endswith("/text")
    vid = path.replace("/text", "")
    try:
        vid = get_video_id(vid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        data = do_fetch(vid, lang)
        if is_text:
            return {"video_id": data["video_id"], "language": data["language_code"], "text": data["text"]}
        return data
    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except NoTranscriptFound:
        raise HTTPException(status_code=404, detail=f"No transcript for language: {lang}")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/transcripts/{video_id}")
async def list_transcripts(
    video_id: str,
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_token(x_proxy_token)
    try:
        vid = get_video_id(video_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return do_list(vid)
    except Exception as e:
        raise HTTPException(status_code=502, detail=str(e))


# ── MCP Endpoint ───────────────────────────────────────────────────────
# Standard JSON-RPC MCP interface. POST JSON-RPC requests, get JSON-RPC responses.
# Compatible with any MCP client that supports HTTP.

MCP_TOOLS = [
    {
        "name": "get_transcript",
        "description": "Get YouTube video transcript with timestamps",
        "inputSchema": {
            "type": "object",
            "properties": {
                "videoId": {"type": "string", "description": "YouTube video ID or URL"},
                "lang": {"type": "string", "description": "Language code", "default": "en"},
            },
            "required": ["videoId"],
        },
    },
    {
        "name": "get_transcript_text",
        "description": "Get YouTube video transcript as plain text",
        "inputSchema": {
            "type": "object",
            "properties": {
                "videoId": {"type": "string", "description": "YouTube video ID or URL"},
                "lang": {"type": "string", "description": "Language code", "default": "en"},
            },
            "required": ["videoId"],
        },
    },
    {
        "name": "list_transcripts",
        "description": "List available transcript languages for a YouTube video",
        "inputSchema": {
            "type": "object",
            "properties": {
                "videoId": {"type": "string", "description": "YouTube video ID or URL"},
            },
            "required": ["videoId"],
        },
    },
]


@app.post("/mcp")
async def mcp_handler(request: Request):
    body = await request.json()
    req_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})
    auth = request.headers.get("x-proxy-token", "")

    if method == "tools/list":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}})

    if method == "tools/call":
        tool = params.get("name", "")
        args = params.get("arguments", {})

        if AUTH_TOKEN and auth != AUTH_TOKEN:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "Unauthorized"}})

        try:
            video_input = args.get("videoId", "")
            lang = args.get("lang", "en")
            vid = get_video_id(video_input)
        except ValueError as e:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}})

        try:
            if tool == "get_transcript":
                data = do_fetch(vid, lang)
                lines = [f"[{s['start']:.1f}s] {s['text']}" for s in data["segments"]]
                text = f"Transcript ({data['language']}):\n" + "\n".join(lines)
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}})

            if tool == "get_transcript_text":
                data = do_fetch(vid, lang)
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": data["text"]}]}})

            if tool == "list_transcripts":
                data = do_list(vid)
                lines = [f"  - {t['language']} ({t['language_code']}){' [auto]' if t['is_generated'] else ''}" for t in data["transcripts"]]
                text = f"Available transcripts for {vid}:\n" + "\n".join(lines)
                return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": text}]}})

            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool}"}})

        except TranscriptsDisabled:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "Transcripts disabled"}})
        except Exception as e:
            return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}})

    if method == "initialize":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "youtube-transcript", "version": "1.0.0"},
            "capabilities": {"tools": {}},
        }})

    if method == "notifications/initialized":
        return JSONResponse({"jsonrpc": "2.0", "id": req_id, "result": {}})

    return JSONResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}})
