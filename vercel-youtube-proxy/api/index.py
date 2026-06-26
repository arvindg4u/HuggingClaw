"""
Vercel YouTube Transcript Proxy — uses youtube-transcript-api directly.
No proxies, no tunnels, no temp files.
"""

import os, re, random
from fastapi import FastAPI, HTTPException, Header, Query
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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
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


def check_auth(token: str):
    if AUTH_TOKEN and token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


def build_session():
    sess = Session()
    sess.headers.update({
        "User-Agent": random.choice(USER_AGENTS),
        "Accept-Language": "en-US,en;q=0.9",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    return sess


@app.get("/health")
async def health():
    return {"status": "ok", "engine": "youtube-transcript-api"}


@app.get("/transcript/{video_id}")
@app.get("/transcript/{video_id}/text")
async def get_transcript(
    video_id: str,
    lang: str = Query("en"),
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_auth(x_proxy_token)
    path = str(video_id)
    is_text = path.endswith("/text")
    vid = path.replace("/text", "")
    try:
        vid = get_video_id(vid)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ytt = YouTubeTranscriptApi(http_client=build_session())
        transcript = ytt.fetch(vid, languages=[lang])
        segments = [{"text": s.text, "start": s.start, "duration": s.duration} for s in transcript.snippets]
        full_text = " ".join(s["text"] for s in segments)

        if is_text:
            return {"video_id": vid, "language": transcript.language_code, "text": full_text}

        return {
            "video_id": vid,
            "language": transcript.language,
            "language_code": transcript.language_code,
            "is_generated": transcript.is_generated,
            "segments": segments,
            "text": full_text,
        }

    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except NoTranscriptFound:
        raise HTTPException(status_code=404, detail=f"No transcript for language: {lang}")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error: {str(e)}")


@app.get("/transcripts/{video_id}")
async def list_transcripts(
    video_id: str,
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    check_auth(x_proxy_token)
    try:
        vid = get_video_id(video_id)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        ytt = YouTubeTranscriptApi(http_client=build_session())
        transcript_list = ytt.list(vid)
        return {
            "video_id": vid,
            "transcripts": [
                {"language": t.language, "language_code": t.language_code, "is_generated": t.is_generated}
                for t in transcript_list
            ],
        }
    except TranscriptsDisabled:
        raise HTTPException(status_code=404, detail="Transcripts disabled")
    except VideoUnavailable:
        raise HTTPException(status_code=404, detail="Video unavailable")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Error: {str(e)}")
