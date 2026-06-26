/**
 * MCP YouTube Transcript Proxy Server
 *
 * Wraps the Render-hosted YouTube Transcript API as MCP tools.
 * Use with any MCP client (Codex CLI, Claude Desktop, Cursor, etc.)
 *
 * Config:
 *   YT_PROXY_BASE  — Render proxy URL (default: https://render-youtube-proxy.onrender.com)
 *   YT_PROXY_TOKEN — Auth token from PROXY_AUTH_TOKEN
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const PROXY_BASE = process.env.YT_PROXY_BASE || "https://render-youtube-proxy.onrender.com";
const PROXY_TOKEN = process.env.YT_PROXY_TOKEN || "";

if (!PROXY_TOKEN) {
  console.error("[yt-mcp] WARNING: YT_PROXY_TOKEN not set — API calls will fail");
}

/**
 * Call the Render YouTube Transcript API
 */
async function callApi(path) {
  const url = `${PROXY_BASE}${path}`;
  const res = await fetch(url, {
    headers: { "X-Proxy-Token": PROXY_TOKEN },
  });
  const body = await res.json();
  if (!res.ok) {
    throw new Error(body.detail || `API error: ${res.status}`);
  }
  return body;
}

// ── MCP Server ────────────────────────────────────────────────────────────
const server = new McpServer({
  name: "youtube-transcript-proxy",
  version: "1.0.0",
});

// ── Tool: get_transcript (with timestamps) ────────────────────────────────
server.tool(
  "get_transcript",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
    lang: z.string().optional().default("en").describe("Language code (e.g., en, es, de)"),
  },
  async ({ videoId, lang }) => {
    const data = await callApi(`/transcript/${encodeURIComponent(videoId)}?lang=${lang}`);
    const segments = data.segments.map((s) => {
      const mins = Math.floor(s.start / 60);
      const secs = Math.floor(s.start % 60);
      return `[${mins}:${secs.toString().padStart(2, "0")}] ${s.text}`;
    });
    return {
      content: [
        {
          type: "text",
          text: `Transcript for video ${data.video_id}\nLanguage: ${data.language} (${data.language_code})\n${segments.join("\n")}`,
        },
      ],
    };
  },
);

// ── Tool: get_transcript_text (plain text, no timestamps) ─────────────────
server.tool(
  "get_transcript_text",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
    lang: z.string().optional().default("en").describe("Language code (e.g., en, es, de)"),
    maxChars: z.number().optional().default(50000).describe("Max characters to return"),
  },
  async ({ videoId, lang, maxChars }) => {
    const data = await callApi(`/transcript/${encodeURIComponent(videoId)}/text?lang=${lang}`);
    const text = data.text.length > maxChars ? data.text.slice(0, maxChars) + "\n\n...[truncated]" : data.text;
    return {
      content: [
        {
          type: "text",
          text: `Transcript for video ${data.video_id}\nLanguage: ${data.language} (${data.language_code})\n\n${text}`,
        },
      ],
    };
  },
);

// ── Tool: list_transcripts (available languages) ──────────────────────────
server.tool(
  "list_transcripts",
  {
    videoId: z.string().describe("YouTube video ID or full URL"),
  },
  async ({ videoId }) => {
    const data = await callApi(`/transcripts/${encodeURIComponent(videoId)}`);
    const lines = data.transcripts.map((t) =>
      `  - ${t.language} (${t.language_code})${t.is_generated ? " [auto-generated]" : ""}`
    );
    return {
      content: [
        {
          type: "text",
          text: `Available transcripts for video ${data.video_id}:\n${lines.join("\n")}`,
        },
      ],
    };
  },
);

// ── Start ─────────────────────────────────────────────────────────────────
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`[yt-mcp] Server started → proxy: ${PROXY_BASE}`);
}

main().catch((err) => {
  console.error("[yt-mcp] Fatal:", err);
  process.exit(1);
});
