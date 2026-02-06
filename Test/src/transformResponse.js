// ─── Chat Completions API  →  Responses API  (response body) ─────────────────
//
// Converts a non-streaming /v1/chat/completions response JSON into the shape
// expected by callers of POST /v1/responses.

import { randomUUID } from "node:crypto";

/**
 * Build a Responses API response object from a Chat Completions response.
 *
 * @param {object} chat   — parsed JSON from LiteLLM /v1/chat/completions
 * @param {string} model  — model name to echo back
 * @returns {object}        Responses API shaped JSON
 */
export function transformResponse(chat, model) {
  const responseId = `resp_${randomUUID()}`;
  const createdAt  = chat.created ?? Math.floor(Date.now() / 1000);
  const choice     = chat.choices?.[0];
  const message    = choice?.message ?? {};

  // ── Build output items ──────────────────────────────────────────────
  const output = [];
  let outputText = "";

  // 1) Text message (if present)
  if (message.content) {
    const msgId = `msg_${randomUUID()}`;
    outputText  = message.content;
    output.push({
      id: msgId,
      type: "message",
      role: "assistant",
      status: "completed",
      content: [
        { type: "output_text", text: message.content },
      ],
    });
  }

  // 2) Tool / function calls
  if (Array.isArray(message.tool_calls)) {
    for (const tc of message.tool_calls) {
      const fcId = `fc_${randomUUID()}`;
      output.push({
        id: fcId,
        type: "function_call",
        call_id: tc.id ?? `call_${randomUUID()}`,
        name: tc.function?.name ?? "",
        arguments: tc.function?.arguments ?? "",
        status: "completed",
      });
    }
  }

  // ── Assemble top-level response ─────────────────────────────────────
  const resp = {
    id: responseId,
    object: "response",
    created_at: createdAt,
    status: "completed",
    model: model ?? chat.model ?? "unknown",
    output,
    output_text: outputText,
  };

  // ── Usage mapping ───────────────────────────────────────────────────
  if (chat.usage) {
    resp.usage = {
      input_tokens:  chat.usage.prompt_tokens     ?? 0,
      output_tokens: chat.usage.completion_tokens  ?? 0,
      total_tokens:  chat.usage.total_tokens       ?? 0,
    };
  }

  return resp;
}
