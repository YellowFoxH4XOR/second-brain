// ─── Configuration ────────────────────────────────────────────────────────────
// All tunables come from environment variables.  No .env library needed —
// just export them or use a .env loader of your choice before starting.

export const LITELLM_BASE_URL = process.env.LITELLM_BASE_URL || "https://api.studi.com";
export const LITELLM_API_KEY  = process.env.LITELLM_API_KEY  || "";

export const PORT              = parseInt(process.env.PORT || "8080", 10);
export const REQUEST_TIMEOUT   = parseInt(process.env.REQUEST_TIMEOUT || "300000", 10); // ms
export const RESPONSE_STORE_MAX = parseInt(process.env.RESPONSE_STORE_MAX || "500", 10);
export const LOG_LEVEL         = process.env.LOG_LEVEL || "info";  // "debug" | "info" | "warn" | "error"
