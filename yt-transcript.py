#!/usr/bin/env python3
"""
YouTube Transcript MCP Server — local yt-dlp + Vercel fallback.

1. Tries yt-dlp with android/tv/ios/web clients
2. Falls back to Vercel API if yt-dlp fails
No proxies, no tunnels.
"""

import sys, json, os, re, tempfile, subprocess, shutil, urllib.request, urllib.error, random

VERCEL_API = os.environ.get("YT_API_BASE", "")
VERCEL_TOKEN = os.environ.get("YT_API_TOKEN", "")
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 Safari/604.1",
]


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


def parse_vtt(text):
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


def fetch_via_ytdlp(video_id, lang="en"):
    """Try yt-dlp with multiple player clients."""
    url = f"https://www.youtube.com/watch?v={video_id}"
    for client in ["android", "tv", "ios", "web", "mweb"]:
        tmpdir = tempfile.mkdtemp()
        try:
            r = subprocess.run(
                ["yt-dlp", "--skip-download", "--write-auto-sub", "--write-subs",
                 "--sub-langs", f"{lang},en", "--sub-format", "vtt", "--convert-subs", "vtt",
                 "--extractor-args", f"youtube:player_client={client}",
                 "--output", os.path.join(tmpdir, "%(id)s"),
                 "--no-warnings", "--quiet", url],
                capture_output=True, text=True, timeout=60,
            )
            for f in os.listdir(tmpdir):
                if f.endswith(".vtt"):
                    with open(os.path.join(tmpdir, f), encoding="utf-8") as fp:
                        text = parse_vtt(fp.read())
                    if text.strip():
                        return {"text": text, "client": client, "source": "yt-dlp"}
        except:
            pass
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    return None


def fetch_via_vercel(video_id, lang="en"):
    """Fallback: call Vercel API."""
    if not VERCEL_API:
        return None
    try:
        req = urllib.request.Request(
            f"{VERCEL_API}/transcript/{video_id}/text?lang={lang}",
            headers={"User-Agent": random.choice(USER_AGENTS)},
        )
        if VERCEL_TOKEN:
            req.add_header("X-Proxy-Token", VERCEL_TOKEN)
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            if data.get("text"):
                return {"text": data["text"], "client": "vercel", "source": "vercel"}
    except:
        pass
    return None


def fetch_info_ytdlp(video_id):
    url = f"https://www.youtube.com/watch?v={video_id}"
    for client in ["android", "tv", "web"]:
        try:
            r = subprocess.run(
                ["yt-dlp", "--skip-download", "--dump-json",
                 "--extractor-args", f"youtube:player_client={client}",
                 "--no-warnings", "--quiet", url],
                capture_output=True, text=True, timeout=30,
            )
            if r.returncode == 0 and r.stdout.strip():
                d = json.loads(r.stdout.strip())
                subs = {**d.get("subtitles", {}), **d.get("automatic_captions", {})}
                return {
                    "title": d.get("title", ""), "duration": d.get("duration", 0),
                    "channel": d.get("channel", ""), "view_count": d.get("view_count", 0),
                    "like_count": d.get("like_count", 0), "transcripts": list(subs.keys()),
                }
        except:
            continue
    return {"title": "", "transcripts": []}


# ── MCP Server ─────────────────────────────────────────────────────────
def handle(request):
    rid = request.get("id")
    method = request.get("method")
    params = request.get("params", {})

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": rid, "result": {"tools": [
            {"name": "get_transcript", "description": "Get transcript with timestamps via yt-dlp",
             "inputSchema": {"type": "object", "properties": {
                 "videoId": {"type": "string", "description": "YouTube video ID or URL"},
                 "lang": {"type": "string", "description": "Language code", "default": "en"},
             }, "required": ["videoId"]}},
            {"name": "get_transcript_text", "description": "Get plain text transcript via yt-dlp",
             "inputSchema": {"type": "object", "properties": {
                 "videoId": {"type": "string", "description": "YouTube video ID or URL"},
                 "lang": {"type": "string", "description": "Language code", "default": "en"},
             }, "required": ["videoId"]}},
            {"name": "get_video_info", "description": "Get video metadata and available transcripts",
             "inputSchema": {"type": "object", "properties": {
                 "videoId": {"type": "string", "description": "YouTube video ID or URL"},
             }, "required": ["videoId"]}},
        ]}}

    elif method == "tools/call":
        tool = params.get("name")
        args = params.get("arguments", {})
        video_input = args.get("videoId", "")
        lang = args.get("lang", "en")
        try:
            video_id = get_video_id(video_input)
        except ValueError as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}}

        try:
            if tool == "get_video_info":
                info = fetch_info_ytdlp(video_id)
                txt = f"Title: {info.get('title', 'N/A')}\nDuration: {info.get('duration', 0)}s\nChannel: {info.get('channel', 'N/A')}\nViews: {info.get('view_count', 0)}\nAvailable transcripts: {', '.join(info.get('transcripts', [])) or 'None'}"
                return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": txt}]}}

            # Try yt-dlp first, then Vercel
            data = fetch_via_ytdlp(video_id, lang)
            if not data:
                data = fetch_via_vercel(video_id, lang)
            if not data:
                raise Exception("Transcript unavailable from all sources")

            text = data["text"]
            src = f"{data['source']} ({data['client']})"
            return {"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": f"Transcript [{src}]:\n\n{text}"}]}}

        except Exception as e:
            return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32000, "message": str(e)}}

    elif method == "initialize":
        return {"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2024-11-05", "serverInfo": {"name": "yt-transcript", "version": "1.0.0"},
            "capabilities": {"tools": {}}}}
    elif method == "notifications/initialized":
        return None
    return {"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": f"Unknown: {method}"}}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
            if resp:
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            continue
        except Exception as e:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
