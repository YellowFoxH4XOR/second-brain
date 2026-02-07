#!/usr/bin/env node
// ─── Responses → Chat Completions Proxy ──────────────────────────────────────
//
//   User / Codex  ──▶  this proxy (/v1/responses)
//                              │  transform request
//                              ▼
//                     LiteLLM (/v1/chat/completions)
//                              │  transform response
//                              ▼
//   User / Codex  ◀──  this proxy (Responses API shape)
//
// Supports both streaming and non-streaming requests.
// Also proxies /v1/chat/completions and /v1/models transparently.

import express       from "express";
import { randomUUID } from "node:crypto";

import {
  LITELLM_BASE_URL,
  LITELLM_API_KEY,
  PORT,
  REQUEST_TIMEOUT,
  LOG_LEVEL,
} from "./config.js";

import { transformRequest }  from "./transformRequest.js";
import { transformResponse } from "./transformResponse.js";
import { StreamHandler }     from "./streamHandler.js";
import { responseStore }     from "./store.js";

// ────────────────────────────────────────────────────────────────────────────────
// Express setup
// ────────────────────────────────────────────────────────────────────────────────

const app = express();

// Parse JSON bodies (generous limit for large conversation histories)
app.use(express.json({ limit: "10mb" }));

// Simple request logger
app.use((req, _res, next) => {
  if (shouldLog("debug")) {
    console.log(`→ ${req.method} ${req.path}`);
  }
  next();
});

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

function shouldLog(level) {
  const levels = { debug: 0, info: 1, warn: 2, error: 3 };
  return (levels[level] ?? 1) >= (levels[LOG_LEVEL] ?? 1);
}

function log(level, ...args) {
  if (shouldLog(level)) console[level === "debug" ? "log" : level](...args);
}

/**
 * Build the headers object to send to LiteLLM.
 * Forwards the caller's Authorization header; falls back to the configured key.
 */
function upstreamHeaders(req) {
  const headers = { "Content-Type": "application/json" };

  const auth = req.get("authorization");
  if (auth) {
    headers["Authorization"] = auth;
  } else if (LITELLM_API_KEY) {
    headers["Authorization"] = `Bearer ${LITELLM_API_KEY}`;
  }

  // Forward OpenAI-specific headers that LiteLLM may inspect
  const org = req.get("openai-organization");
  if (org) headers["OpenAI-Organization"] = org;

  return headers;
}

// ────────────────────────────────────────────────────────────────────────────────
// POST /v1/responses   — the main transformation endpoint
// ────────────────────────────────────────────────────────────────────────────────

app.post("/v1/responses", async (req, res) => {
  const body  = req.body ?? {};
  const model = body.model ?? "unknown";

  try {
    // ── Transform request ───────────────────────────────────────────────
    const ccBody = transformRequest(body);

    log("debug", "Transformed CC body:", JSON.stringify(ccBody, null, 2));

    const isStream = !!body.stream;

    // ── Forward to LiteLLM ──────────────────────────────────────────────
    const upstream = await fetch(`${LITELLM_BASE_URL}/v1/chat/completions`, {
      method:  "POST",
      headers: upstreamHeaders(req),
      body:    JSON.stringify(ccBody),
      signal:  AbortSignal.timeout(REQUEST_TIMEOUT),
    });

    // ── Upstream error (non-2xx) — relay it ─────────────────────────────
    if (!upstream.ok) {
      const errText = await upstream.text().catch(() => "");
      log("warn", `LiteLLM ${upstream.status}: ${errText.slice(0, 500)}`);
      res.status(upstream.status);
      res.set("Content-Type", upstream.headers.get("content-type") || "application/json");
      return res.send(errText || JSON.stringify({ error: { message: "Upstream error", code: upstream.status } }));
    }

    // ════════════════════════════════════════════════════════════════════
    // NON-STREAMING
    // ════════════════════════════════════════════════════════════════════
    if (!isStream) {
      const chatJson = await upstream.json();
      const respBody = transformResponse(chatJson, model);

      // Store for later retrieval
      responseStore.set(respBody.id, respBody);

      return res.json(respBody);
    }

    // ════════════════════════════════════════════════════════════════════
    // STREAMING
    // ════════════════════════════════════════════════════════════════════
    res.writeHead(200, {
      "Content-Type":  "text/event-stream",
      "Cache-Control": "no-cache",
      Connection:      "keep-alive",
      "X-Accel-Buffering": "no",   // disable nginx buffering if present
    });

    const handler = new StreamHandler(model);

    // Read the SSE byte-stream from LiteLLM line-by-line
    const reader  = upstream.body;
    let   buffer  = "";

    const decoder = new TextDecoder();

    for await (const raw of reader) {
      buffer += typeof raw === "string" ? raw : decoder.decode(raw, { stream: true });

      // Split on double-newline (SSE event boundary) or single newline
      let nlIdx;
      while ((nlIdx = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, nlIdx).trim();
        buffer = buffer.slice(nlIdx + 1);

        if (!line) continue;                     // blank line (event separator)
        if (line.startsWith(":")) continue;      // SSE comment / keep-alive

        if (line.startsWith("data: ")) {
          const payload = line.slice(6);

          if (payload === "[DONE]") {
            // Some backends skip the finish_reason chunk.  Ensure we
            // always emit response.completed before the stream closes.
            const finalEvents = handler.forceComplete();
            for (const ev of finalEvents) res.write(ev);
            continue;
          }

          try {
            const chunk  = JSON.parse(payload);
            const events = handler.processChunk(chunk);
            for (const ev of events) res.write(ev);
          } catch (parseErr) {
            log("warn", "Failed to parse SSE chunk:", payload.slice(0, 200), parseErr.message);
          }
        }
      }
    }

    // Flush anything remaining in buffer
    if (buffer.trim()) {
      const remaining = buffer.trim();
      if (remaining.startsWith("data: ") && remaining.slice(6) !== "[DONE]") {
        try {
          const chunk  = JSON.parse(remaining.slice(6));
          const events = handler.processChunk(chunk);
          for (const ev of events) res.write(ev);
        } catch { /* ignore */ }
      }
    }

    // Safety net: if the upstream never sent finish_reason or [DONE],
    // force-emit response.completed so Codex CLI doesn't retry forever.
    const trailing = handler.forceComplete();
    for (const ev of trailing) res.write(ev);

    // Store the completed response
    const completed = handler.getCompletedResponse();
    responseStore.set(completed.id, completed);

    res.end();
  } catch (err) {
    log("error", "POST /v1/responses error:", err);

    if (res.headersSent) {
      // Already streaming — force-complete so Codex CLI gets response.completed
      try {
        const trailing = handler.forceComplete();
        for (const ev of trailing) res.write(ev);
      } catch { /* ignore */ }
      return res.end();
    }

    res.status(502).json({
      error: {
        message: `Proxy error: ${err.message}`,
        type:    "proxy_error",
        code:    "upstream_failure",
      },
    });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// GET /v1/responses/:id   — retrieve a stored response
// ────────────────────────────────────────────────────────────────────────────────

app.get("/v1/responses/:id", (req, res) => {
  const stored = responseStore.get(req.params.id);
  if (!stored) {
    return res.status(404).json({
      error: { message: "Response not found", type: "not_found", code: "not_found" },
    });
  }
  res.json(stored);
});

// ────────────────────────────────────────────────────────────────────────────────
// DELETE /v1/responses/:id
// ────────────────────────────────────────────────────────────────────────────────

app.delete("/v1/responses/:id", (req, res) => {
  responseStore.delete(req.params.id);
  res.json({ id: req.params.id, deleted: true });
});

// ────────────────────────────────────────────────────────────────────────────────
// POST /v1/chat/completions   — transparent pass-through to LiteLLM
// ────────────────────────────────────────────────────────────────────────────────

app.post("/v1/chat/completions", async (req, res) => {
  try {
    const isStream = !!req.body?.stream;

    const upstream = await fetch(`${LITELLM_BASE_URL}/v1/chat/completions`, {
      method:  "POST",
      headers: upstreamHeaders(req),
      body:    JSON.stringify(req.body),
      signal:  AbortSignal.timeout(REQUEST_TIMEOUT),
    });

    res.status(upstream.status);

    if (!isStream || !upstream.ok) {
      // Non-streaming or error → relay body as-is
      res.set("Content-Type", upstream.headers.get("content-type") || "application/json");
      const text = await upstream.text();
      return res.send(text);
    }

    // Streaming pass-through (pipe raw SSE)
    res.writeHead(200, {
      "Content-Type":  "text/event-stream",
      "Cache-Control": "no-cache",
      Connection:      "keep-alive",
    });

    const decoder = new TextDecoder();
    for await (const chunk of upstream.body) {
      res.write(typeof chunk === "string" ? chunk : decoder.decode(chunk, { stream: true }));
    }

    res.end();
  } catch (err) {
    log("error", "POST /v1/chat/completions error:", err);
    if (!res.headersSent) {
      res.status(502).json({ error: { message: err.message } });
    } else {
      res.end();
    }
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// GET /v1/models   — transparent pass-through
// ────────────────────────────────────────────────────────────────────────────────

app.get("/v1/models", async (req, res) => {
  try {
    const upstream = await fetch(`${LITELLM_BASE_URL}/v1/models`, {
      headers: upstreamHeaders(req),
      signal:  AbortSignal.timeout(30_000),
    });
    res.status(upstream.status);
    res.set("Content-Type", upstream.headers.get("content-type") || "application/json");
    const text = await upstream.text();
    res.send(text);
  } catch (err) {
    log("error", "GET /v1/models error:", err);
    res.status(502).json({ error: { message: err.message } });
  }
});

// ────────────────────────────────────────────────────────────────────────────────
// Health check
// ────────────────────────────────────────────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    stored_responses: responseStore.size,
    litellm_base_url: LITELLM_BASE_URL,
  });
});

// Catch-all for unknown routes
app.use((_req, res) => {
  res.status(404).json({
    error: { message: "Not found — this proxy serves /v1/responses, /v1/chat/completions, /v1/models" },
  });
});

// ────────────────────────────────────────────────────────────────────────────────
// Start
// ────────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`
┌─────────────────────────────────────────────────────────────┐
│  Responses → Chat Completions Proxy                         │
│                                                             │
│  Listening :  http://0.0.0.0:${String(PORT).padEnd(5)}                          │
│  Upstream  :  ${LITELLM_BASE_URL.padEnd(43)} │
│                                                             │
│  Endpoints:                                                 │
│    POST /v1/responses          (transform + proxy)          │
│    GET  /v1/responses/:id      (retrieve stored)            │
│    POST /v1/chat/completions   (pass-through)               │
│    GET  /v1/models             (pass-through)               │
│    GET  /health                                             │
└─────────────────────────────────────────────────────────────┘
`);
});

export default app;
