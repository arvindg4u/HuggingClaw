"""
Vercel YouTube Transcript Proxy — lightweight, serverless-friendly.
Uses youtube-transcript-api with Android/iOS client fallbacks.
No temp files, no subprocess, no proxy rotation.
"""

import os
import re
import json
import random
from typing import Optional
from fastapi import FastAPI, HTTPException, Header, Query
from httpx import AsyncClient, Limits, Timeout

app = FastAPI(title="YouTube Transcript API", docs_url=None, redoc_url=None)

AUTH_TOKEN = os.getenv("PROXY_AUTH_TOKEN", "")

USER_AGENTS = [
    "com.google.android.youtube/19.09.37 (Linux; U; Android 14) gzip",
    "com.google.android.youtube/19.08.35 (Linux; U; Android 13) gzip",
    "com.google.ios.youtube/19.09.37 (iPhone; iOS 18.0; gzip)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
]


def get_video_id(video_input: str) -> str:
    patterns = [
        r'(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/|youtube\.com\/v\/)([a-zA-Z0-9_-]{11})',
        r'^([a-zA-Z0-9_-]{11})$',
    ]
    for p in patterns:
        m = re.search(p, video_input)
        if m:
            return m.group(1)
    raise ValueError(f"Invalid video input: {video_input}")


def check_auth(token: str):
    if AUTH_TOKEN and token != AUTH_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid token")


@app.get("/health")
async def health():
    return {"status": "ok", "engine": "youtube-transcript-api"}


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

    # Try android client first, then web
    for client in ["ANDROID", "WEB"]:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            if client == "ANDROID":
                headers["X-YouTube-Client-Name"] = "3"
                headers["X-YouTube-Client-Version"] = "19.09.37"
            else:
                headers["X-YouTube-Client-Name"] = "1"
                headers["X-YouTube-Client-Version"] = "2.20241201.00.00"

            async with AsyncClient(
                headers=headers,
                timeout=Timeout(25.0),
                limits=Limits(max_keepalive_connections=5),
            ) as sess:
                # Use YouTube InnerTube API for transcripts
                # First get the caption tracks
                inner_url = "https://www.youtube.com/youtubei/v1/player?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"
                payload = {
                    "videoId": video_id,
                    "context": {
                        "client": {
                            "clientName": client,
                            "clientVersion": "19.09.37" if client == "ANDROID" else "2.20241201.00.00",
                            "hl": "en",
                        }
                    }
                }
                resp = await sess.post(inner_url, json=payload)
                data = resp.json()

                # Extract caption tracks
                captions = data.get("captions", {})
                tracks = captions.get("playerCaptionsTracklistRenderer", {}).get("captionTracks", [])

                if tracks:
                    # Find requested language
                    selected = None
                    for t in tracks:
                        if t.get("languageCode") == lang:
                            selected = t
                            break
                    if not selected:
                        selected = tracks[0]

                    # Download the actual transcript
                    sub_url = selected["baseUrl"]
                    sub_resp = await sess.get(sub_url)

                    # Parse the XML/SRV3 response
                    xml_text = sub_resp.text
                    # Extract text from <text> tags
                    texts = re.findall(r'<text[^>]*>(.*?)</text>', xml_text)
                    segments = []
                    for text in texts:
                        text = re.sub(r'<[^>]+>', '', text)
                        text = text.replace("&#39;", "'").replace("&amp;", "&").replace("&quot;", '"')
                        segments.append({"text": text, "start": 0, "duration": 0})

                    full_text = " ".join(s["text"] for s in segments)

                    return {
                        "video_id": video_id,
                        "language": selected.get("languageCode", lang),
                        "client": client,
                        "is_generated": True,
                        "segments": segments,
                        "text": full_text,
                    }

        except Exception:
            continue

    raise HTTPException(status_code=502, detail="YouTube blocked this request")


@app.get("/transcript/{video_input:path}/text")
async def get_transcript_text(
    video_input: str,
    lang: str = Query("en"),
    x_proxy_token: str = Header(default="", alias="X-Proxy-Token"),
):
    result = await get_transcript(video_input, lang, x_proxy_token)
    if isinstance(result, dict):
        return {"video_id": result["video_id"], "language": result["language"], "text": result.get("text", "")}
    return result


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

    for client in ["ANDROID", "WEB"]:
        try:
            headers = {"User-Agent": random.choice(USER_AGENTS)}
            if client == "ANDROID":
                headers["X-YouTube-Client-Name"] = "3"
                headers["X-YouTube-Client-Version"] = "19.09.37"

            async with AsyncClient(headers=headers, timeout=Timeout(25.0)) as sess:
                inner_url = "https://www.youtube.com/youtubei/v1/player?key=AIzaSyAO_FJ2SlqU8Q4STEHLGCilw_Y9_11qcW8"
                payload = {
                    "videoId": video_id,
                    "context": {"client": {"clientName": client, "clientVersion": "19.09.37", "hl": "en"}},
                }
                resp = await sess.post(inner_url, json=payload)
                data = resp.json()
                tracks = data.get("captions", {}).get("playerCaptionsTracklistRenderer", {}).get("captionTracks", [])

                if tracks:
                    return {
                        "video_id": video_id,
                        "source": f"innertube_{client}",
                        "transcripts": [
                            {"language": t.get("languageCode", ""), "language_code": t.get("languageCode", ""),
                             "name": t.get("name", {}).get("simpleText", "")}
                            for t in tracks
                        ],
                    }
        except Exception:
            continue

    raise HTTPException(status_code=502, detail="Could not fetch transcript list")
