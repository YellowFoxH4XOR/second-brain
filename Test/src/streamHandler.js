// ─── Streaming SSE transformer ───────────────────────────────────────────────
//
// Converts a stream of Chat Completions *chunks* (SSE `data:` payloads) into
// the named-event SSE format that the OpenAI Responses API produces.
//
// Lifecycle events emitted (in order):
//
//   response.created
//   response.output_item.added       (message or function_call)
//   response.content_part.added      (for text messages)
//   response.output_text.delta       (repeated, text deltas)
//   response.output_text.done
//   response.content_part.done
//   response.output_item.done        (message)
//   response.function_call_arguments.delta  (repeated, for each tool call)
//   response.function_call_arguments.done
//   response.output_item.done        (function_call)
//   response.completed
//
// Each public method returns an *array* of fully-formatted SSE strings
// (ready to write to the HTTP response) so the caller can just iterate + write.

import { randomUUID } from "node:crypto";

export class StreamHandler {
  /**
   * @param {string} model  — model name to echo in the response envelope
   */
  constructor(model) {
    this.responseId   = `resp_${randomUUID()}`;
    this.model        = model;
    this.createdAt    = Math.floor(Date.now() / 1000);

    // ── Lifecycle flags ───────────────────────────────────────────────
    this.started          = false;   // have we emitted response.created?
    this.messageStarted   = false;   // emitted output_item.added for the text msg?
    this.messageFinished  = false;   // emitted output_item.done  for the text msg?

    // ── Accumulators ──────────────────────────────────────────────────
    this.messageId        = `msg_${randomUUID()}`;
    this.messageOutputIdx = -1;       // assigned when first content delta arrives
    this.accumulatedText  = "";

    /** Map<toolCallIndex, {id, callId, name, args, outputIdx, fcId}> */
    this.toolCalls        = new Map();
    this.nextOutputIdx    = 0;

    /** Completed output items in order (sparse array). */
    this.outputItems      = [];

    this.usage            = null;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Public API
  // ──────────────────────────────────────────────────────────────────────

  /**
   * Feed one parsed Chat Completions chunk object and receive back zero or
   * more SSE event strings.
   *
   * @param {object} chunk  — a single `chat.completion.chunk` JSON object
   * @returns {string[]}      ready-to-send SSE event strings
   */
  processChunk(chunk) {
    const events = [];

    // ── First chunk → emit response.created ───────────────────────────
    if (!this.started) {
      this.started = true;
      events.push(
        this.#sse("response.created", {
          id:         this.responseId,
          object:     "response",
          created_at: this.createdAt,
          status:     "in_progress",
          model:      this.model,
          output:     [],
        })
      );
    }

    const choice = chunk.choices?.[0];

    // Usage-only trailing chunk (no choice)
    if (!choice) {
      if (chunk.usage) this.usage = chunk.usage;
      return events;
    }

    const delta        = choice.delta ?? {};
    const finishReason = choice.finish_reason ?? null;

    // ── Text content deltas ───────────────────────────────────────────
    if (delta.content != null && delta.content !== "") {
      if (!this.messageStarted) {
        this.messageStarted   = true;
        this.messageOutputIdx = this.nextOutputIdx++;

        events.push(
          this.#sse("response.output_item.added", {
            type:         "response.output_item.added",
            output_index: this.messageOutputIdx,
            item: {
              id:      this.messageId,
              type:    "message",
              role:    "assistant",
              status:  "in_progress",
              content: [],
            },
          })
        );

        events.push(
          this.#sse("response.content_part.added", {
            type:          "response.content_part.added",
            output_index:  this.messageOutputIdx,
            content_index: 0,
            part:          { type: "output_text", text: "" },
          })
        );
      }

      this.accumulatedText += delta.content;

      events.push(
        this.#sse("response.output_text.delta", {
          type:          "response.output_text.delta",
          output_index:  this.messageOutputIdx,
          content_index: 0,
          delta:         delta.content,
        })
      );
    }

    // ── Tool-call deltas ──────────────────────────────────────────────
    if (Array.isArray(delta.tool_calls)) {
      for (const tcDelta of delta.tool_calls) {
        const idx = tcDelta.index ?? 0;

        if (!this.toolCalls.has(idx)) {
          // ── New tool call ────────────────────────────────────────────
          // If a text message is still open, close it first so output
          // indices stay sequential.
          if (this.messageStarted && !this.messageFinished) {
            events.push(...this.#finaliseMessage());
          }

          const fcId     = `fc_${randomUUID()}`;
          const callId   = tcDelta.id ?? `call_${randomUUID()}`;
          const name     = tcDelta.function?.name ?? "";
          const argsInit = tcDelta.function?.arguments ?? "";
          const outIdx   = this.nextOutputIdx++;

          this.toolCalls.set(idx, {
            id:        tcDelta.id ?? callId,
            callId,
            name,
            args:      argsInit,
            outputIdx: outIdx,
            fcId,
          });

          events.push(
            this.#sse("response.output_item.added", {
              type:         "response.output_item.added",
              output_index: outIdx,
              item: {
                id:        fcId,
                type:      "function_call",
                call_id:   callId,
                name,
                arguments: "",
                status:    "in_progress",
              },
            })
          );

          if (argsInit) {
            events.push(
              this.#sse("response.function_call_arguments.delta", {
                type:         "response.function_call_arguments.delta",
                output_index: outIdx,
                delta:        argsInit,
              })
            );
          }
        } else {
          // ── Continuation of existing tool call ───────────────────────
          const tc = this.toolCalls.get(idx);

          if (tcDelta.function?.name && !tc.name) {
            tc.name = tcDelta.function.name;
          }

          if (tcDelta.function?.arguments) {
            tc.args += tcDelta.function.arguments;
            events.push(
              this.#sse("response.function_call_arguments.delta", {
                type:         "response.function_call_arguments.delta",
                output_index: tc.outputIdx,
                delta:        tcDelta.function.arguments,
              })
            );
          }
        }
      }
    }

    // ── Usage (may arrive in the last chunk) ──────────────────────────
    if (chunk.usage) this.usage = chunk.usage;

    // ── Finish reason → finalise everything ───────────────────────────
    if (finishReason) {
      events.push(...this.#finalise());
    }

    return events;
  }

  /**
   * Return the completed Responses-API response object (useful for caching
   * in the response store after the stream ends).
   */
  getCompletedResponse() {
    const output = this.outputItems.filter(Boolean);
    const resp = {
      id:          this.responseId,
      object:      "response",
      created_at:  this.createdAt,
      status:      "completed",
      model:       this.model,
      output,
      output_text: this.accumulatedText,
    };
    if (this.usage) {
      resp.usage = {
        input_tokens:  this.usage.prompt_tokens    ?? 0,
        output_tokens: this.usage.completion_tokens ?? 0,
        total_tokens:  this.usage.total_tokens      ?? 0,
      };
    }
    return resp;
  }

  // ──────────────────────────────────────────────────────────────────────
  // Private helpers
  // ──────────────────────────────────────────────────────────────────────

  /** Close the text message (output_text.done + content_part.done + output_item.done). */
  #finaliseMessage() {
    if (this.messageFinished) return [];
    this.messageFinished = true;

    const events = [];
    const idx    = this.messageOutputIdx;

    events.push(
      this.#sse("response.output_text.done", {
        type:          "response.output_text.done",
        output_index:  idx,
        content_index: 0,
        text:          this.accumulatedText,
      })
    );

    events.push(
      this.#sse("response.content_part.done", {
        type:          "response.content_part.done",
        output_index:  idx,
        content_index: 0,
        part:          { type: "output_text", text: this.accumulatedText },
      })
    );

    const messageItem = {
      id:      this.messageId,
      type:    "message",
      role:    "assistant",
      status:  "completed",
      content: [{ type: "output_text", text: this.accumulatedText }],
    };
    this.outputItems[idx] = messageItem;

    events.push(
      this.#sse("response.output_item.done", {
        type:         "response.output_item.done",
        output_index: idx,
        item:         messageItem,
      })
    );

    return events;
  }

  /** Close everything and emit response.completed. */
  #finalise() {
    const events = [];

    // Close text message if still open
    if (this.messageStarted && !this.messageFinished) {
      events.push(...this.#finaliseMessage());
    }

    // Close each tool call (ordered by their tool_calls index)
    const sorted = [...this.toolCalls.entries()].sort((a, b) => a[0] - b[0]);
    for (const [, tc] of sorted) {
      events.push(
        this.#sse("response.function_call_arguments.done", {
          type:         "response.function_call_arguments.done",
          output_index: tc.outputIdx,
          arguments:    tc.args,
        })
      );

      const fcItem = {
        id:        tc.fcId,
        type:      "function_call",
        call_id:   tc.callId,
        name:      tc.name,
        arguments: tc.args,
        status:    "completed",
      };
      this.outputItems[tc.outputIdx] = fcItem;

      events.push(
        this.#sse("response.output_item.done", {
          type:         "response.output_item.done",
          output_index: tc.outputIdx,
          item:         fcItem,
        })
      );
    }

    // ── response.completed ────────────────────────────────────────────
    events.push(
      this.#sse("response.completed", this.getCompletedResponse())
    );

    return events;
  }

  /** Format a single named SSE event. */
  #sse(event, data) {
    return `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  }
}
