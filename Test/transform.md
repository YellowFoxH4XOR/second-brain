# Transformation Rules — Detailed Documentation

This document describes **every** transformation this proxy performs when
converting between the OpenAI **Responses API** (`POST /v1/responses`) and the
**Chat Completions API** (`POST /v1/chat/completions`) that LiteLLM understands.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Request Transformation (Responses → Chat Completions)](#2-request-transformation)
   - 2.1 [Message Construction (`input` → `messages`)](#21-message-construction)
   - 2.2 [Content Normalisation](#22-content-normalisation)
   - 2.3 [Tool Definitions](#23-tool-definitions)
   - 2.4 [Tool Choice](#24-tool-choice)
   - 2.5 [Scalar Parameters](#25-scalar-parameters)
   - 2.6 [Response Format (`text.format` → `response_format`)](#26-response-format)
   - 2.7 [Streaming Flag](#27-streaming-flag)
   - 2.8 [Reasoning Effort](#28-reasoning-effort)
   - 2.9 [Silently Ignored Fields](#29-silently-ignored-fields)
3. [Response Transformation (Chat Completions → Responses)](#3-response-transformation)
   - 3.1 [Text Output](#31-text-output)
   - 3.2 [Tool Call Output](#32-tool-call-output)
   - 3.3 [Usage Mapping](#33-usage-mapping)
   - 3.4 [ID Generation](#34-id-generation)
4. [Streaming Transformation](#4-streaming-transformation)
   - 4.1 [SSE Format Difference](#41-sse-format-difference)
   - 4.2 [State Machine](#42-state-machine)
   - 4.3 [Text Streaming Lifecycle](#43-text-streaming-lifecycle)
   - 4.4 [Tool Call Streaming Lifecycle](#44-tool-call-streaming-lifecycle)
   - 4.5 [Mixed (Text + Tool Calls) Streaming](#45-mixed-text--tool-calls-streaming)
   - 4.6 [Edge Cases](#46-edge-cases)
5. [Pass-Through Endpoints](#5-pass-through-endpoints)
6. [Error Handling](#6-error-handling)
7. [In-Memory Response Store](#7-in-memory-response-store)

---

## 1. Architecture Overview

```
 ┌──────────────┐       ┌─────────────────────┐        ┌──────────────────┐
 │              │ POST  │                     │  POST  │                  │
 │  Codex /     │──────▶│   This Proxy        │───────▶│  LiteLLM         │
 │  Client      │  /v1/ │   (Node.js/Express) │  /v1/  │  api.studi.com   │
 │              │ resp. │                     │  chat/ │                  │
 │              │◀──────│   Transforms both   │◀───────│  → Bedrock       │
 │              │ Resp. │   request & response │  CC    │                  │
 └──────────────┘  API  └─────────────────────┘  API   └──────────────────┘
```

The proxy is a **protocol compiler** — it never modifies semantic content, only
reshapes the JSON envelope so that a Responses-API-speaking client (like Codex)
can talk to a Chat-Completions-only backend (LiteLLM → Bedrock).

### Source files

| File | Responsibility |
|---|---|
| `src/transformRequest.js` | Responses request body → Chat Completions request body |
| `src/transformResponse.js` | Chat Completions response body → Responses response body (non-streaming) |
| `src/streamHandler.js` | Chat Completions SSE chunks → Responses API SSE events (streaming) |
| `src/index.js` | Express server, routing, upstream fetch, SSE piping |
| `src/store.js` | Bounded in-memory response cache |
| `src/config.js` | Environment-variable-based configuration |

---

## 2. Request Transformation

**File:** `src/transformRequest.js` — exported function `transformRequest(body)`

Takes the raw JSON body from `POST /v1/responses` and returns a JSON body
suitable for `POST /v1/chat/completions`.

### 2.1 Message Construction

The Responses API uses an `input` field (plus an optional `instructions` field)
to convey conversation history. Chat Completions uses a flat `messages[]` array.
The conversion is handled by `buildMessages(body)`.

#### Step 1 — System prompt from `instructions`

If the request has an `instructions` field, it becomes the **first** message:

```
Responses API                          Chat Completions
─────────────                          ────────────────
{ "instructions": "You are X" }   →   messages[0] = { role: "system", content: "You are X" }
```

#### Step 2 — `input` as a string

The simplest case. A bare string becomes a single user message:

```
{ "input": "Hello" }              →   messages[1] = { role: "user", content: "Hello" }
```

#### Step 3 — `input` as an array of items

This is the complex case. The array can contain different item types, each
requiring specific handling:

| Responses item `type` | Conversion | Notes |
|---|---|---|
| `"message"` | `{ role, content }` | Role is mapped (see below), content is normalised |
| `"function_call"` | Accumulated into an assistant `tool_calls[]` | Multiple consecutive ones are grouped into a single assistant message |
| `"function_call_output"` | `{ role: "tool", tool_call_id, content }` | Triggers flush of any pending tool calls first |
| `"item_reference"` | **Skipped** | Server-side references can't be resolved in a stateless proxy |
| Bare `{role, content}` (no `type`) | Treated as `"message"` | Fallback for older/simpler formats |

#### Tool call grouping algorithm

In the Responses API, each `function_call` is a separate input item. In Chat
Completions, multiple tool calls must be grouped into a **single** assistant
message's `tool_calls` array. The proxy uses a **pending-flush** pattern:

```
┌─ For each input item ──────────────────────────────────────────────────┐
│                                                                        │
│  function_call?  ──▶  Accumulate in pendingToolCalls[]                 │
│                                                                        │
│  message or function_call_output?  ──▶  FLUSH pending tool calls:      │
│    • If last message is assistant without tool_calls → attach there    │
│    • Otherwise → create new { role:"assistant", content:null,          │
│                                tool_calls: [...] }                     │
│    Then add the current item as a new message.                         │
│                                                                        │
│  End of array?  ──▶  FLUSH any remaining pending tool calls            │
└────────────────────────────────────────────────────────────────────────┘
```

**Example — full round-trip conversation:**

```json
// Responses API input array
[
  { "type": "message", "role": "user", "content": "What's the weather?" },
  { "type": "message", "role": "assistant", "content": [{"type":"output_text","text":"Let me check."}] },
  { "type": "function_call", "call_id": "call_1", "name": "get_weather", "arguments": "{\"city\":\"NYC\"}" },
  { "type": "function_call_output", "call_id": "call_1", "output": "{\"temp\":72}" },
  { "type": "message", "role": "user", "content": "Thanks!" }
]
```

```json
// Resulting Chat Completions messages[]
[
  { "role": "user", "content": "What's the weather?" },
  {
    "role": "assistant",
    "content": "Let me check.",
    "tool_calls": [{
      "id": "call_1",
      "type": "function",
      "function": { "name": "get_weather", "arguments": "{\"city\":\"NYC\"}" }
    }]
  },
  { "role": "tool", "tool_call_id": "call_1", "content": "{\"temp\":72}" },
  { "role": "user", "content": "Thanks!" }
]
```

Notice how the `function_call` item was **merged** into the preceding assistant
message, and `function_call_output` became a `tool` role message.

#### Role mapping

| Responses role | Chat Completions role | Reason |
|---|---|---|
| `user` | `user` | Same |
| `assistant` | `assistant` | Same |
| `system` | `system` | Same |
| `developer` | `system` | Chat Completions has no `developer` role; semantically equivalent to `system` |
| `tool` | `tool` | Same |

---

### 2.2 Content Normalisation

The Responses API uses typed content parts (`input_text`, `output_text`,
`input_image`, etc.). Chat Completions uses different type names (`text`,
`image_url`). The `convertContent()` function handles the mapping.

| Responses content part | Chat Completions content part | Notes |
|---|---|---|
| `{ type: "input_text", text }` | `{ type: "text", text }` | Renamed |
| `{ type: "output_text", text }` | `{ type: "text", text }` | Renamed (when sent as history) |
| `{ type: "text", text }` | `{ type: "text", text }` | Pass-through |
| `{ type: "input_image", image_url }` | `{ type: "image_url", image_url: { url } }` | Restructured |
| `{ type: "input_audio", ... }` | `{ type: "text", text: "[audio]" }` | Bedrock doesn't support audio; flattened to marker |
| `{ type: "refusal", refusal }` | `{ type: "text", text }` | Flattened |
| Plain `string` content | `string` | Passed through as-is |

**Simplification rule:** If all content parts are text, they are **collapsed into
a single plain string** for maximum backend compatibility. Multipart arrays are
only preserved when non-text parts (images) are present.

```
// Input: array of text parts
[{type:"input_text", text:"Hello "}, {type:"input_text", text:"world"}]
// Output: plain string
"Hello world"

// Input: mixed text + image
[{type:"input_text", text:"Look at this"}, {type:"input_image", image_url:"https://..."}]
// Output: multipart array (preserved)
[{type:"text", text:"Look at this"}, {type:"image_url", image_url:{url:"https://..."}}]
```

---

### 2.3 Tool Definitions

The Responses API and Chat Completions API both support function tools but use
**different JSON shapes**.

```
Responses API                              Chat Completions API
─────────────                              ────────────────────
{                                          {
  "type": "function",                        "type": "function",
  "name": "get_weather",          →          "function": {
  "description": "Get weather",                "name": "get_weather",
  "parameters": { ... },                       "description": "Get weather",
  "strict": true                               "parameters": { ... },
}                                              "strict": true
                                             }
                                           }
```

Key difference: In Responses, `name`/`description`/`parameters`/`strict` sit at
the **top level**. In Chat Completions, they're nested under a `function` key.

**Built-in tool types are silently dropped:**

| Tool type | Action |
|---|---|
| `function` | Transformed and forwarded |
| `web_search` | **Dropped** (no CC equivalent) |
| `file_search` | **Dropped** |
| `code_interpreter` | **Dropped** |
| `computer_use_preview` | **Dropped** |

---

### 2.4 Tool Choice

`tool_choice` controls whether the model must/can/cannot use tools.

| Format | Responses API | Chat Completions API | Proxy action |
|---|---|---|---|
| String | `"auto"`, `"required"`, `"none"` | Same | Pass through |
| Object (Responses) | `{type:"function", name:"fn"}` | N/A | Restructure → `{type:"function", function:{name:"fn"}}` |
| Object (CC) | N/A | `{type:"function", function:{name:"fn"}}` | Pass through (if already in CC format) |

The proxy checks whether the object already has a `function` sub-key to avoid
double-wrapping.

---

### 2.5 Scalar Parameters

These fields map **directly** (same name and semantics) and are only included
in the output if present in the input:

| Responses API | Chat Completions API | Notes |
|---|---|---|
| `temperature` | `temperature` | 1:1 |
| `top_p` | `top_p` | 1:1 |
| `presence_penalty` | `presence_penalty` | 1:1 |
| `frequency_penalty` | `frequency_penalty` | 1:1 |
| `seed` | `seed` | 1:1 |
| `stop` | `stop` | String or array, 1:1 |
| `max_output_tokens` | `max_tokens` | **Renamed** |
| `parallel_tool_calls` | `parallel_tool_calls` | 1:1 |
| `service_tier` | `service_tier` | 1:1 |
| `logprobs` | `logprobs` | 1:1 |
| `top_logprobs` | `top_logprobs` | 1:1 |

---

### 2.6 Response Format

The Responses API nests structured output config under `text.format`. Chat
Completions uses a top-level `response_format`.

```
Responses API                              Chat Completions API
─────────────                              ────────────────────
{                                          {
  "text": {                       →          "response_format": {
    "format": {                                "type": "json_object"
      "type": "json_object"                  }
    }                                        }
  }
}

{                                          {
  "text": {                       →          "response_format": {
    "format": {                                "type": "json_schema",
      "type": "json_schema",                   "json_schema": {
      "name": "my_schema",                       "name": "my_schema",
      "schema": { ... },                         "schema": { ... },
      "strict": true                             "strict": true
    }                                          }
  }                                          }
}                                          }
```

If `text.format.type` is `"text"` or absent, `response_format` is omitted
(Chat Completions defaults to text).

---

### 2.7 Streaming Flag

When `stream: true`:

1. The Chat Completions request also gets `stream: true`.
2. We inject `stream_options: { include_usage: true }` so LiteLLM returns token
   counts in the final streaming chunk (used in the `response.completed` event).

---

### 2.8 Reasoning Effort

For o-series models (o1, o3, etc.) the Responses API accepts:

```json
{ "reasoning": { "effort": "high" } }
```

This is mapped to:

```json
{ "reasoning_effort": "high" }
```

LiteLLM may or may not forward this to the backend; the proxy passes it through
without modification.

---

### 2.9 Silently Ignored Fields

These Responses API fields have no Chat Completions equivalent and are
**dropped without error**:

| Field | Reason |
|---|---|
| `store` | Server-side storage concern; not applicable |
| `metadata` | Arbitrary user metadata; no CC equivalent |
| `truncation` | Context-window management; CC returns error on overflow |
| `previous_response_id` | Would require full conversation replay; client typically sends full `input` anyway |
| `include` | Controls optional response fields; proxy always includes what's available |

---

## 3. Response Transformation

**File:** `src/transformResponse.js` — exported function `transformResponse(chat, model)`

Takes a complete (non-streaming) Chat Completions response and returns a
Responses API response envelope.

### 3.1 Text Output

```
Chat Completions                           Responses API
────────────────                           ─────────────
{                                          {
  "choices": [{                              "output": [{
    "message": {                               "id": "msg_<uuid>",
      "role": "assistant",          →          "type": "message",
      "content": "Hello world"                 "role": "assistant",
    }                                          "status": "completed",
  }]                                           "content": [{
}                                                "type": "output_text",
                                                 "text": "Hello world"
                                               }]
                                             }],
                                             "output_text": "Hello world"
                                           }
```

The `output_text` top-level field is a convenience shorthand that concatenates
all text from all output messages.

---

### 3.2 Tool Call Output

Each `tool_calls[]` entry in the Chat Completions response becomes a separate
`function_call` output item:

```
Chat Completions                           Responses API
────────────────                           ─────────────
{                                          {
  "choices": [{                              "output": [
    "message": {                               // ... text message if any ...
      "tool_calls": [{                         {
        "id": "call_abc",          →             "id": "fc_<uuid>",
        "type": "function",                      "type": "function_call",
        "function": {                            "call_id": "call_abc",
          "name": "get_weather",                 "name": "get_weather",
          "arguments": "{...}"                   "arguments": "{...}",
        }                                        "status": "completed"
      }]                                       }
    }                                        ]
  }]                                       }
}
```

- `tool_calls[].id` → `call_id` (preserved exactly)
- `tool_calls[].function.name` → `name` (hoisted to top level)
- `tool_calls[].function.arguments` → `arguments` (hoisted to top level)
- A new `id` (`fc_<uuid>`) is generated for the Responses output item

---

### 3.3 Usage Mapping

```
Chat Completions                           Responses API
────────────────                           ─────────────
{                                          {
  "usage": {                                 "usage": {
    "prompt_tokens": 42,          →            "input_tokens": 42,
    "completion_tokens": 15,                   "output_tokens": 15,
    "total_tokens": 57                         "total_tokens": 57
  }                                          }
}                                          }
```

| Chat Completions field | Responses API field |
|---|---|
| `prompt_tokens` | `input_tokens` |
| `completion_tokens` | `output_tokens` |
| `total_tokens` | `total_tokens` |

---

### 3.4 ID Generation

All IDs are freshly generated UUIDs with type-specific prefixes:

| Entity | Prefix | Example |
|---|---|---|
| Response | `resp_` | `resp_a1b2c3d4-...` |
| Message output item | `msg_` | `msg_e5f6g7h8-...` |
| Function call output item | `fc_` | `fc_i9j0k1l2-...` |

The `created_at` timestamp is taken from the Chat Completions `created` field
when available, otherwise falls back to `Date.now()`.

---

## 4. Streaming Transformation

**File:** `src/streamHandler.js` — exported class `StreamHandler`

This is the most complex piece. It converts a stream of **unnamed**
Chat Completions SSE chunks into **named** Responses API SSE events.

### 4.1 SSE Format Difference

**Chat Completions streaming** uses unnamed data lines:

```
data: {"id":"chatcmpl-x","choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}

data: {"id":"chatcmpl-x","choices":[{"delta":{"content":"Hello"},"finish_reason":null}]}

data: {"id":"chatcmpl-x","choices":[{"delta":{},"finish_reason":"stop"}]}

data: [DONE]
```

**Responses API streaming** uses named events:

```
event: response.created
data: {"id":"resp_x","object":"response","status":"in_progress","output":[]}

event: response.output_text.delta
data: {"type":"response.output_text.delta","output_index":0,"content_index":0,"delta":"Hello"}

event: response.completed
data: {"id":"resp_x","object":"response","status":"completed","output":[...]}
```

Key differences:
- Responses API has an `event:` field on every SSE message
- Responses API has lifecycle events (created, item added, item done, completed)
- Responses API uses `output_index` / `content_index` for addressing

---

### 4.2 State Machine

The `StreamHandler` class maintains the following state:

```
StreamHandler
├── responseId        (string)    Generated once at construction
├── model             (string)    Echoed in all events
├── createdAt         (number)    Unix timestamp
│
├── started           (bool)      Has response.created been emitted?
├── messageStarted    (bool)      Has output_item.added been emitted for the text message?
├── messageFinished   (bool)      Has output_item.done been emitted for the text message?
│
├── messageId         (string)    "msg_<uuid>" — stable across the stream
├── messageOutputIdx  (number)    Position in the output[] array (-1 until assigned)
├── accumulatedText   (string)    Full text accumulated from all content deltas
│
├── toolCalls         (Map)       index → { id, callId, name, args, outputIdx, fcId }
├── nextOutputIdx     (number)    Counter for sequential output item indices
├── outputItems       (array)     Sparse array of completed output items
│
└── usage             (object)    Token counts from the final chunk
```

Each call to `processChunk(chunk)` returns an array of fully-formatted SSE
strings ready to `res.write()`.

---

### 4.3 Text Streaming Lifecycle

When the model produces text content, these events are emitted in order:

```
 Chat Completions chunk                 Responses API event(s)
 ──────────────────────                 ──────────────────────

 1. First chunk arrives          →      event: response.created
    (any chunk)                         data: { id, object:"response", status:"in_progress", ... }

 2. First content delta          →      event: response.output_item.added
    delta.content = "He"                data: { output_index:0, item:{ id:"msg_x", type:"message",
                                                role:"assistant", status:"in_progress", content:[] } }

                                        event: response.content_part.added
                                        data: { output_index:0, content_index:0,
                                                part:{ type:"output_text", text:"" } }

                                        event: response.output_text.delta
                                        data: { output_index:0, content_index:0, delta:"He" }

 3. Subsequent content deltas    →      event: response.output_text.delta
    delta.content = "llo"               data: { ..., delta:"llo" }
    delta.content = " world"            (one event per chunk)

 4. finish_reason = "stop"       →      event: response.output_text.done
                                        data: { output_index:0, content_index:0, text:"Hello world" }

                                        event: response.content_part.done
                                        data: { output_index:0, content_index:0,
                                                part:{ type:"output_text", text:"Hello world" } }

                                        event: response.output_item.done
                                        data: { output_index:0, item:{ id:"msg_x", type:"message",
                                                role:"assistant", status:"completed",
                                                content:[{type:"output_text",text:"Hello world"}] } }

                                        event: response.completed
                                        data: { id:"resp_x", status:"completed", output:[...],
                                                output_text:"Hello world", usage:{...} }
```

---

### 4.4 Tool Call Streaming Lifecycle

When the model invokes functions (no text content):

```
 Chat Completions chunk                 Responses API event(s)
 ──────────────────────                 ──────────────────────

 1. First chunk arrives          →      event: response.created

 2. New tool call appears                event: response.output_item.added
    delta.tool_calls = [{               data: { output_index:0, item:{ id:"fc_x",
      index: 0,                                 type:"function_call", call_id:"call_1",
      id: "call_1",                             name:"get_weather", arguments:"",
      function: {                               status:"in_progress" } }
        name: "get_weather",
        arguments: ""           →       (if initial arguments non-empty:)
      }                                 event: response.function_call_arguments.delta
    }]                                  data: { output_index:0, delta:"..." }

 3. Argument deltas              →      event: response.function_call_arguments.delta
    delta.tool_calls = [{               data: { output_index:0, delta:"{\"ci" }
      index: 0,
      function: {
        arguments: "{\"ci"
      }
    }]

 4. More argument deltas         →      (one delta event per chunk)

 5. finish_reason = "tool_calls" →      event: response.function_call_arguments.done
                                        data: { output_index:0, arguments:"{\"city\":\"NYC\"}" }

                                        event: response.output_item.done
                                        data: { output_index:0, item:{ ..., status:"completed",
                                                arguments:"{\"city\":\"NYC\"}" } }

                                        event: response.completed
                                        data: { ... full response object ... }
```

**Multiple parallel tool calls** come with different `index` values in the
`delta.tool_calls` array. Each gets its own sequential `output_index`.

---

### 4.5 Mixed (Text + Tool Calls) Streaming

When the model produces **both** text and tool calls in one turn:

1. Text content deltas arrive first (output_index 0)
2. When the first tool call delta arrives:
   - The text message is **finalised** (output_text.done → content_part.done → output_item.done)
   - The tool call gets the next output_index (1, 2, ...)
3. Tool call argument deltas follow
4. On `finish_reason`, remaining tool calls are finalised, then `response.completed`

```
output_index assignment:
  0  →  text message
  1  →  first tool call (tool_calls[0])
  2  →  second tool call (tool_calls[1])
  ...
```

This ensures the `output[]` array in the final `response.completed` event
matches what a non-streaming response would produce.

---

### 4.6 Edge Cases

| Scenario | Handling |
|---|---|
| `[DONE]` received without `finish_reason` | Proxy synthesises a `{finish_reason:"stop"}` chunk to trigger finalisation |
| Malformed JSON in an SSE chunk | Logged as warning, chunk skipped, stream continues |
| Usage arrives in a separate trailing chunk (no `choices`) | Captured in `this.usage`; included in `response.completed` |
| Upstream connection drops mid-stream | Error event emitted if possible, then connection closed |
| Empty `delta.content` (empty string) | Ignored (no event emitted) to avoid empty deltas |
| `delta.content = null` | Ignored |
| Tool call `function.name` arrives in a later chunk | Merged into existing tool call record |

---

## 5. Pass-Through Endpoints

These endpoints forward requests **without transformation**, for clients that
need direct Chat Completions or model listing access.

| Endpoint | Upstream | Streaming | Notes |
|---|---|---|---|
| `POST /v1/chat/completions` | `POST {LITELLM}/v1/chat/completions` | Piped raw | Body, headers, status forwarded as-is |
| `GET /v1/models` | `GET {LITELLM}/v1/models` | No | Response forwarded as-is |

---

## 6. Error Handling

### Upstream errors (non-2xx from LiteLLM)

- The HTTP status code is relayed to the client.
- The response body is forwarded as-is (LiteLLM already returns OpenAI-shaped errors).

### Proxy errors (network failure, timeout, parse error)

- **Non-streaming:** Returns `502` with a JSON error body:
  ```json
  { "error": { "message": "Proxy error: <details>", "type": "proxy_error", "code": "upstream_failure" } }
  ```

- **Streaming (headers already sent):** Emits an error SSE event and closes:
  ```
  event: error
  data: {"error":{"message":"<details>"}}
  ```

### Timeouts

Controlled by `REQUEST_TIMEOUT` env var (default 300 seconds). Uses
`AbortSignal.timeout()` on the upstream `fetch()` call.

---

## 7. In-Memory Response Store

**File:** `src/store.js`

A bounded `Map` that caches the most recent N completed response objects
(default N = 500, configurable via `RESPONSE_STORE_MAX`).

**Endpoints served:**

| Method | Path | Behaviour |
|---|---|---|
| `GET` | `/v1/responses/:id` | Returns stored response or 404 |
| `DELETE` | `/v1/responses/:id` | Removes from store, returns `{deleted:true}` |

**Eviction:** When the store is full, the oldest entry (first-inserted key in
the Map) is deleted before inserting a new one (FIFO eviction).

Both streaming and non-streaming responses are stored after completion, using
the `resp_<uuid>` response ID as the key.

> **Production note:** This is an in-memory store. It does not survive restarts
> and is not shared across instances. Replace with Redis / DynamoDB / etc. for
> production multi-instance deployments.
