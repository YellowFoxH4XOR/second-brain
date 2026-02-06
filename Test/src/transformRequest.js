// ─── Responses API  →  Chat Completions API  (request body) ───────────────────
//
// Converts a POST /v1/responses body into a POST /v1/chat/completions body
// that LiteLLM (and any OpenAI-compatible backend) understands.
//
// Key mappings
//   instructions           → system message (first in messages[])
//   input  (string)        → single user message
//   input  (item[])        → messages[] with proper role / tool grouping
//   max_output_tokens      → max_tokens
//   tools  (Responses fmt) → tools  (Chat Completions fmt)
//   text.format            → response_format
//   Everything else maps 1-to-1 or is silently ignored.

// ────────────────────────────────────────────────────────────────────────────────
// Helpers
// ────────────────────────────────────────────────────────────────────────────────

/** Map Responses API role names to Chat Completions equivalents. */
function mapRole(role) {
  if (role === "developer") return "system";
  return role; // user, assistant, system, tool all pass through
}

/**
 * Normalise a content field (string | ContentPart[]) into what Chat Completions
 * expects.  If the content is purely text we collapse to a plain string for
 * maximum compatibility with backends.
 */
function convertContent(content) {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return String(content ?? "");

  const parts = [];
  let hasNonText = false;

  for (const part of content) {
    if (typeof part === "string") {
      parts.push({ type: "text", text: part });
      continue;
    }
    switch (part.type) {
      case "input_text":
        parts.push({ type: "text", text: part.text });
        break;
      case "output_text":
        parts.push({ type: "text", text: part.text });
        break;
      case "text":
        parts.push({ type: "text", text: part.text });
        break;
      case "input_image":
        hasNonText = true;
        parts.push({
          type: "image_url",
          image_url: { url: part.image_url ?? part.url ?? "" },
        });
        break;
      case "input_audio":
        // Bedrock has no audio support — flatten to marker
        parts.push({ type: "text", text: "[audio]" });
        break;
      case "refusal":
        parts.push({ type: "text", text: part.refusal ?? "" });
        break;
      default:
        // Best-effort: if there's a text field, use it
        if (part.text) {
          parts.push({ type: "text", text: part.text });
        } else {
          parts.push({ type: "text", text: `[${part.type ?? "unknown"}]` });
        }
    }
  }

  // Simplify to plain string whenever possible (widest backend compat)
  if (!hasNonText) {
    const joined = parts.map((p) => p.text).join("");
    return joined;
  }
  if (parts.length === 1 && parts[0].type === "text") return parts[0].text;
  return parts;
}

/**
 * Flush accumulated tool_calls into messages[].
 * We try to attach them to the *preceding* assistant message; if there is
 * none we create a synthetic assistant message with `content: null`.
 */
function flushToolCalls(messages, pending) {
  if (pending.length === 0) return;

  const last = messages[messages.length - 1];
  if (last && last.role === "assistant" && !last.tool_calls) {
    last.tool_calls = pending.splice(0);
    // Chat Completions spec: when tool_calls present, content should be null
    // if it was empty / undefined.
    if (!last.content) last.content = null;
  } else {
    messages.push({
      role: "assistant",
      content: null,
      tool_calls: pending.splice(0),
    });
  }
}

// ────────────────────────────────────────────────────────────────────────────────
// Input  →  messages
// ────────────────────────────────────────────────────────────────────────────────

function buildMessages(body) {
  const messages = [];
  const pendingToolCalls = [];

  // 1) System message from `instructions`
  if (body.instructions) {
    messages.push({ role: "system", content: body.instructions });
  }

  const input = body.input;

  // ── Simple string input ───────────────────────────────────────────────
  if (typeof input === "string") {
    messages.push({ role: "user", content: input });
    return messages;
  }

  // ── No input at all (edge case) ──────────────────────────────────────
  if (!Array.isArray(input)) return messages;

  // ── Array of input items ──────────────────────────────────────────────
  for (const item of input) {
    // Determine type — items may or may not have an explicit `type` field.
    // Bare {role, content} objects (no type) are treated as messages.
    const type = item.type ?? (item.role ? "message" : null);

    switch (type) {
      case "message": {
        flushToolCalls(messages, pendingToolCalls);
        messages.push({
          role: mapRole(item.role),
          content: convertContent(item.content),
        });
        break;
      }

      case "function_call": {
        // Accumulate; will be flushed as a single assistant message later.
        pendingToolCalls.push({
          id: item.call_id ?? item.id ?? "",
          type: "function",
          function: {
            name: item.name,
            arguments: item.arguments ?? "",
          },
        });
        break;
      }

      case "function_call_output": {
        flushToolCalls(messages, pendingToolCalls);
        messages.push({
          role: "tool",
          tool_call_id: item.call_id,
          content:
            typeof item.output === "string"
              ? item.output
              : JSON.stringify(item.output ?? ""),
        });
        break;
      }

      case "item_reference": {
        // Can't resolve server-side references in a stateless proxy — skip
        break;
      }

      default: {
        // Fallback: bare {role, content} without `type`
        if (item.role) {
          flushToolCalls(messages, pendingToolCalls);
          messages.push({
            role: mapRole(item.role),
            content: convertContent(item.content ?? ""),
          });
        }
        // Unknown shape — silently ignore
      }
    }
  }

  // Flush any remaining tool calls
  flushToolCalls(messages, pendingToolCalls);

  return messages;
}

// ────────────────────────────────────────────────────────────────────────────────
// Tools  →  Chat Completions format
// ────────────────────────────────────────────────────────────────────────────────

function buildTools(tools) {
  if (!Array.isArray(tools) || tools.length === 0) return undefined;

  const mapped = [];
  for (const tool of tools) {
    // Only function tools are portable to Chat Completions.
    // Built-in Responses-only tools (web_search, file_search, code_interpreter,
    // computer_use_preview) are silently dropped — they have no equivalent.
    if (tool.type !== "function") continue;

    mapped.push({
      type: "function",
      function: {
        name: tool.name,
        description: tool.description,
        ...(tool.parameters ? { parameters: tool.parameters } : {}),
        ...(tool.strict !== undefined ? { strict: tool.strict } : {}),
      },
    });
  }

  return mapped.length > 0 ? mapped : undefined;
}

// ────────────────────────────────────────────────────────────────────────────────
// tool_choice mapping
// ────────────────────────────────────────────────────────────────────────────────

function buildToolChoice(toolChoice) {
  if (toolChoice === undefined || toolChoice === null) return undefined;
  // String values pass straight through ("auto", "required", "none")
  if (typeof toolChoice === "string") return toolChoice;
  // Object form — Responses API may use {type:"function", name:"..."}
  // while Chat Completions expects {type:"function", function:{name:"..."}}
  if (typeof toolChoice === "object" && toolChoice.type === "function") {
    if (toolChoice.function) return toolChoice; // already CC format
    return {
      type: "function",
      function: { name: toolChoice.name },
    };
  }
  return toolChoice;
}

// ────────────────────────────────────────────────────────────────────────────────
// response_format  (text.format → response_format)
// ────────────────────────────────────────────────────────────────────────────────

function buildResponseFormat(body) {
  const fmt = body.text?.format;
  if (!fmt) return undefined;

  if (fmt.type === "json_object") {
    return { type: "json_object" };
  }
  if (fmt.type === "json_schema") {
    return {
      type: "json_schema",
      json_schema: {
        name: fmt.name,
        schema: fmt.schema,
        ...(fmt.strict !== undefined ? { strict: fmt.strict } : {}),
      },
    };
  }
  // "text" or unknown — omit (default behaviour)
  return undefined;
}

// ────────────────────────────────────────────────────────────────────────────────
// Main entry point
// ────────────────────────────────────────────────────────────────────────────────

/**
 * Convert a full Responses API request body into a Chat Completions request body.
 *
 * @param {object} body  — raw JSON body from POST /v1/responses
 * @returns {object}       Chat Completions request body
 */
export function transformRequest(body) {
  const cc = {
    model: body.model,
    messages: buildMessages(body),
  };

  // ── Scalar parameters (direct mapping) ──────────────────────────────
  if (body.temperature !== undefined)       cc.temperature       = body.temperature;
  if (body.top_p !== undefined)             cc.top_p             = body.top_p;
  if (body.presence_penalty !== undefined)  cc.presence_penalty  = body.presence_penalty;
  if (body.frequency_penalty !== undefined) cc.frequency_penalty = body.frequency_penalty;
  if (body.seed !== undefined)              cc.seed              = body.seed;

  // max_output_tokens  →  max_tokens
  if (body.max_output_tokens !== undefined) cc.max_tokens = body.max_output_tokens;

  // stop sequences
  if (body.stop !== undefined) cc.stop = body.stop;

  // ── Tools ───────────────────────────────────────────────────────────
  const tools = buildTools(body.tools);
  if (tools) cc.tools = tools;

  const toolChoice = buildToolChoice(body.tool_choice);
  if (toolChoice !== undefined) cc.tool_choice = toolChoice;

  if (body.parallel_tool_calls !== undefined) {
    cc.parallel_tool_calls = body.parallel_tool_calls;
  }

  // ── response_format ─────────────────────────────────────────────────
  const responseFormat = buildResponseFormat(body);
  if (responseFormat) cc.response_format = responseFormat;

  // ── Streaming ───────────────────────────────────────────────────────
  if (body.stream) {
    cc.stream = true;
    // Ask LiteLLM to include usage in the final streaming chunk
    cc.stream_options = { include_usage: true };
  }

  // ── Reasoning effort (for o-series models through LiteLLM) ─────────
  if (body.reasoning?.effort) {
    cc.reasoning_effort = body.reasoning.effort;
  }

  // ── service_tier ────────────────────────────────────────────────────
  if (body.service_tier !== undefined) cc.service_tier = body.service_tier;

  // ── logprobs ────────────────────────────────────────────────────────
  if (body.logprobs !== undefined) cc.logprobs = body.logprobs;
  if (body.top_logprobs !== undefined) cc.top_logprobs = body.top_logprobs;

  return cc;
}
