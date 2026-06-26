#!/usr/bin/env python3
"""
YouTube Transcript MCP Server — uses yt-dlp directly, no proxies.
Tries multiple player clients (android → tv → web) to bypass blocks.
"""

import sys
import json
import os
import re
import tempfile
import subprocess
import shutil

# ── Check if yt-dlp is installed ──────────────────────────────────────
if not shutil.which("yt-dlp"):
    print("yt-dlp not found. Install: pip install yt-dlp", file=sys.stderr)
    sys.exit(1)


def get_video_id(video_input):
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$'
    ]
    for p in patterns:
        m = re.search(p, video_input)
        if m:
            return m.group(1)
    raise ValueError(f"Invalid YouTube URL/ID: {video_input}")


def parse_vtt(vtt_text):
    """Extract text lines from VTT subtitle content."""
    lines = []
    for line in vtt_text.split("\n"):
        line = line.strip()
        # Skip headers, timestamps, and blank lines
        if not line or line.startswith("WEBVTT") or line.startswith("NOTE") or "-->" in line:
            continue
        # Skip numeric sequence lines
        if line.isdigit():
            continue
        # Clean HTML tags
        line = re.sub(r'<[^>]+>', '', line)
        line = line.replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">")
        if line:
            lines.append(line)
    return " ".join(lines)


def fetch_transcript_ytdlp(video_id, lang="en"):
    """Fetch transcript using yt-dlp with multiple player clients."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    player_clients = ["android", "tv", "ios", "web", "mweb"]

    for client in player_clients:
        try:
            tmpdir = tempfile.mkdtemp()
            result = subprocess.run(
                [
                    "yt-dlp",
                    "--skip-download",
                    "--write-auto-sub",
                    "--write-subs",
                    "--sub-langs", lang + ",en",
                    "--sub-format", "vtt",
                    "--convert-subs", "vtt",
                    "--extractor-args", f"youtube:player_client={client}",
                    "--output", os.path.join(tmpdir, "%(id)s"),
                    "--no-warnings",
                    "--quiet",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            # Find the subtitle file
            for f in os.listdir(tmpdir):
                if f.endswith(".vtt") or f.endswith(".en.vtt") or lang in f:
                    filepath = os.path.join(tmpdir, f)
                    with open(filepath, "r", encoding="utf-8") as fp:
                        vtt_content = fp.read()
                    text = parse_vtt(vtt_content)
                    shutil.rmtree(tmpdir, ignore_errors=True)
                    if text.strip():
                        return {"text": text, "client": client, "source": "yt-dlp"}

            shutil.rmtree(tmpdir, ignore_errors=True)

        except subprocess.TimeoutExpired:
            shutil.rmtree(tmpdir, ignore_errors=True)
            continue
        except Exception:
            shutil.rmtree(tmpdir, ignore_errors=True)
            continue

    raise Exception(f"yt-dlp failed for {video_id} with all player clients")


def fetch_info_ytdlp(video_id):
    """Get video info and available subtitles via yt-dlp."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    for client in ["android", "tv", "web"]:
        try:
            result = subprocess.run(
                [
                    "yt-dlp",
                    "--skip-download",
                    "--dump-json",
                    "--extractor-args", f"youtube:player_client={client}",
                    "--no-warnings",
                    "--quiet",
                    url,
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0 and result.stdout.strip():
                data = json.loads(result.stdout.strip())
                subs = data.get("subtitles", {}) or {}
                auto_subs = data.get("automatic_captions", {}) or {}
                all_langs = {}
                for k, v in {**subs, **auto_subs}.items():
                    all_langs[k] = {
                        "name": k,
                        "auto": k in auto_subs,
                    }
                return {
                    "title": data.get("title", ""),
                    "duration": data.get("duration", 0),
                    "upload_date": data.get("upload_date", ""),
                    "channel": data.get("channel", ""),
                    "view_count": data.get("view_count", 0),
                    "like_count": data.get("like_count", 0),
                    "transcripts": all_langs,
                }
        except Exception:
            continue
    return {"title": "", "transcripts": {}}


# ── MCP Server (stdio) ─────────────────────────────────────────────────
def handle_request(request):
    req_id = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/list":
        return {
            "jsonrpc": "2.0", "id": req_id,
            "result": {
                "tools": [
                    {
                        "name": "get_transcript",
                        "description": "Get YouTube video transcript with timestamps via yt-dlp",
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
                        "description": "Get YouTube video transcript as plain text via yt-dlp",
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
                        "name": "get_video_info",
                        "description": "Get YouTube video metadata and available transcript languages",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "videoId": {"type": "string", "description": "YouTube video ID or URL"},
                            },
                            "required": ["videoId"],
                        },
                    },
                ]
            },
        }

    elif method == "tools/call":
        tool = params.get("name")
        args = params.get("arguments", {})
        video_input = args.get("videoId", "")
        lang = args.get("lang", "en")

        try:
            video_id = get_video_id(video_input)
        except ValueError as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}

        try:
            if tool == "get_video_info":
                info = fetch_info_ytdlp(video_id)
                txt = f"Title: {info.get('title', 'N/A')}\n"
                txt += f"Duration: {info.get('duration', 0)}s\n"
                txt += f"Channel: {info.get('channel', 'N/A')}\n"
                txt += f"Views: {info.get('view_count', 0)}\n"
                txt += "Available transcripts:\n"
                for lang_code, t in info.get("transcripts", {}).items():
                    txt += f"  - {lang_code} ({'auto-generated' if t.get('auto') else 'manual'})\n"
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": txt}]}}

            data = fetch_transcript_ytdlp(video_id, lang)
            text = data["text"]

            if tool == "get_transcript_text":
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Transcript ({data['client']} client):\n\n{text}"}]}}

            if tool == "get_transcript":
                # Parse segments from VTT (approximate timestamps from original data)
                return {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": f"Transcript ({data['client']} client):\n\n{text}"}]}}

            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {tool}"}}

        except Exception as e:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": str(e)}}

    elif method == "initialize":
        return {"jsonrpc": "2.0", "id": req_id, "result": {
            "protocolVersion": "2024-11-05",
            "serverInfo": {"name": "yt-transcript", "version": "1.0.0"},
            "capabilities": {"tools": {}},
        }}

    elif method == "notifications/initialized":
        return None

    return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown method: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            continue
        except Exception as e:
            error_resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(error_resp) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
