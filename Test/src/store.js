// ─── In-memory response store ────────────────────────────────────────────────
//
// Simple bounded Map that keeps the N most-recent Responses-API response
// objects so that:
//   • GET /v1/responses/:id   can retrieve them
//   • previous_response_id    could be resolved (future enhancement)
//
// In production you'd replace this with Redis / DynamoDB / etc.

import { RESPONSE_STORE_MAX } from "./config.js";

class ResponseStore {
  constructor(maxSize = RESPONSE_STORE_MAX) {
    /** @type {Map<string, object>} */
    this.store   = new Map();
    this.maxSize = maxSize;
  }

  /** Save a completed response.  Evicts oldest entry when full. */
  set(id, response) {
    if (this.store.size >= this.maxSize) {
      // Delete the oldest (first-inserted) key
      const oldest = this.store.keys().next().value;
      this.store.delete(oldest);
    }
    this.store.set(id, response);
  }

  /** Retrieve a stored response by ID, or undefined. */
  get(id) {
    return this.store.get(id);
  }

  /** Check existence. */
  has(id) {
    return this.store.has(id);
  }

  /** Delete a stored response. Returns true if it existed. */
  delete(id) {
    return this.store.delete(id);
  }

  get size() {
    return this.store.size;
  }
}

// Singleton
export const responseStore = new ResponseStore();
