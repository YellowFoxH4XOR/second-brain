# Responses → Chat Completions Proxy

A lightweight Node.js (Express) proxy that sits between **OpenAI Codex / Responses API clients** and a **LiteLLM instance** that only speaks Chat Completions.

```
 Codex / Client                 This Proxy                    LiteLLM / Bedrock
 ─────────────  POST /v1/responses  ──────────────  POST /v1/chat/completions  ──────────────
                (Responses API)     transform req   (Chat Completions API)
                                    ──────────────
                                    transform resp
 ◀─────────────  Responses shape  ◀─────────────── Chat Completions shape  ◀──────────────
```

## Quick start

```bash
# 1. Install
npm install

# 2. Configure (copy and edit)
cp .env.example .env

# 3. Run
npm start

# Or with live-reload during development (Node 18.11+)
npm run dev
```

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `LITELLM_BASE_URL` | `https://api.studi.com` | Base URL of your LiteLLM instance |
| `LITELLM_API_KEY` | _(empty)_ | Default API key for LiteLLM (caller's `Authorization` header takes priority) |
| `PORT` | `8080` | Port this proxy listens on |
| `REQUEST_TIMEOUT` | `300000` | Upstream request timeout in ms |
| `RESPONSE_STORE_MAX` | `500` | Max responses to cache in memory |
| `LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |

## Endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/v1/responses` | **Main endpoint** — accepts Responses API, transforms to Chat Completions, forwards to LiteLLM, transforms response back. Supports `stream: true`. |
| `GET` | `/v1/responses/:id` | Retrieve a previously returned response from the in-memory store |
| `DELETE` | `/v1/responses/:id` | Delete a stored response |
| `POST` | `/v1/chat/completions` | Transparent pass-through to LiteLLM (streaming included) |
| `GET` | `/v1/models` | Transparent pass-through to LiteLLM |
| `GET` | `/health` | Health check |

## Using with Codex

Point Codex at this proxy instead of the OpenAI API:

```bash
# Set the base URL to this proxy
export OPENAI_BASE_URL=http://localhost:8080/v1
export OPENAI_API_KEY=your-litellm-key

# Run Codex as normal — it sends /v1/responses, proxy handles the rest
codex "explain this codebase"
```

## What gets transformed

### Request (`/v1/responses` → `/v1/chat/completions`)

| Responses API field | Chat Completions field | Notes |
|---|---|---|
| `model` | `model` | Pass-through |
| `instructions` | `messages[0]` (system) | Becomes the first system message |
| `input` (string) | `messages[{role:"user"}]` | Single user message |
| `input` (array) | `messages[]` | Full conversation reconstruction — handles `message`, `function_call`, `function_call_output` items |
| `max_output_tokens` | `max_tokens` | Renamed |
| `temperature`, `top_p`, etc. | Same | Direct pass-through |
| `tools` (function type) | `tools` | Restructured: top-level `name`/`description`/`parameters` → nested under `function` key |
| `tools` (built-in types) | _(dropped)_ | `web_search`, `file_search`, `code_interpreter` have no CC equivalent |
| `tool_choice` | `tool_choice` | Pass-through (with format normalization) |
| `text.format` | `response_format` | `json_object` / `json_schema` mapping |
| `stream` | `stream` + `stream_options` | Adds `include_usage: true` |
| `reasoning.effort` | `reasoning_effort` | For o-series models |

### Response (`/v1/chat/completions` → `/v1/responses`)

| Chat Completions field | Responses API field |
|---|---|
| `choices[0].message.content` | `output[].type:"message"` with `output_text` content |
| `choices[0].message.tool_calls` | `output[].type:"function_call"` items |
| `usage.prompt_tokens` | `usage.input_tokens` |
| `usage.completion_tokens` | `usage.output_tokens` |

### Streaming

| Chat Completions chunk event | Responses API SSE event |
|---|---|
| First `delta` | `response.created`, `response.output_item.added`, `response.content_part.added` |
| `delta.content` | `response.output_text.delta` |
| `delta.tool_calls` (new) | `response.output_item.added` (function_call) |
| `delta.tool_calls` (args) | `response.function_call_arguments.delta` |
| `finish_reason: "stop"` | `response.output_text.done`, `response.content_part.done`, `response.output_item.done`, `response.completed` |
| `finish_reason: "tool_calls"` | `response.function_call_arguments.done`, `response.output_item.done`, `response.completed` |

## Architecture

```
src/
├── index.js               Express server, routes, proxy plumbing
├── config.js              Environment-based configuration
├── transformRequest.js    Responses API → Chat Completions (request body)
├── transformResponse.js   Chat Completions → Responses API (non-streaming response)
├── streamHandler.js       Chat Completions chunks → Responses API SSE events
└── store.js               Bounded in-memory response cache
```

## Requirements

- Node.js **≥ 18** (uses native `fetch`, `crypto.randomUUID`, async iterators on fetch body)
- Express 4.x

No other runtime dependencies.
