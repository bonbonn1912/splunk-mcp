import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { SplunkMcpError } from "./errors.js";
import type { Redactor } from "./redact.js";

export type Row = Record<string, unknown>;

const RAW_LIMIT = 2000;

/** Removes Splunk-internal fields and shortens _raw after any redaction. */
export function cleanRow(row: Row, fields?: string[]): Row {
  const out: Row = {};
  const wanted = fields && fields.length > 0 ? new Set(fields) : undefined;
  for (const [k, v] of Object.entries(row)) {
    if (wanted) {
      if (!wanted.has(k)) continue;
    } else if (k.startsWith("_") && k !== "_time" && k !== "_raw") {
      continue;
    }
    if (k === "_raw" && typeof v === "string" && v.length > RAW_LIMIT) {
      out[k] = `${v.slice(0, RAW_LIMIT)}… [${v.length - RAW_LIMIT} more chars]`;
    } else {
      out[k] = v;
    }
  }
  return out;
}

export interface Payload {
  data: unknown;
  meta?: Record<string, unknown>;
  hint?: string;
  /** Only server-generated job identifiers may bypass content redaction. */
  controlDataKeys?: readonly "sid"[];
}

/**
 * Serialises a result as compact JSON. If `data` is an array and the output
 * would exceed the limit, rows are dropped from the end (never mid-JSON) and
 * the truncation is reported in meta + hint.
 */
let redactor: Redactor | undefined;

/** Every successful tool result passes through ok(), so this covers all tools. */
export function setRedactor(r: Redactor | undefined): void {
  redactor = r;
}

/** Apply the configured redactor to a complete value (including its two-pass scan). */
export function applyRedaction<T>(value: T): T {
  return redactor ? redactor.apply(value) : value;
}

const CONTROL_META_KEYS = ["sid", "environment", "offset", "next_offset", "count", "total"] as const;

/** Redact content together, while preserving the server's paging/job controls. */
function sanitizePayload(payload: Payload): Payload {
  if (!redactor) return payload;
  const meta = { ...(payload.meta ?? {}) };
  const controlMeta: Record<string, unknown> = {};
  for (const key of CONTROL_META_KEYS) {
    if (!Object.hasOwn(meta, key)) continue;
    controlMeta[key] = meta[key];
    delete meta[key];
  }
  // Only the server's metadata link embeds the complete search. A data row's
  // own web_url field remains ordinary content and is still redacted.
  delete meta.web_url;
  let data = payload.data;
  const controlData: Record<string, unknown> = {};
  if (payload.controlDataKeys && data && typeof data === "object" && !Array.isArray(data)) {
    const obj = { ...(data as Record<string, unknown>) };
    for (const key of payload.controlDataKeys) {
      if (!Object.hasOwn(obj, key)) continue;
      controlData[key] = obj[key];
      delete obj[key];
    }
    data = obj;
  }
  // The tuple keeps envelope names out of the key blacklist and still learns
  // sensitive values across data, metadata and hints in the same two passes.
  const [safeData, safeMeta, safeHint] = redactor.apply([data, meta, payload.hint] as const);
  return {
    data: Object.keys(controlData).length > 0 ? { ...(safeData as Record<string, unknown>), ...controlData } : safeData,
    meta: { ...safeMeta, ...controlMeta },
    hint: safeHint,
  };
}

export function ok(payload: Payload, maxChars: number, truncationHint?: string): CallToolResult {
  const sanitized = sanitizePayload(payload);
  let data = sanitized.data;
  const meta: Record<string, unknown> = { ...(sanitized.meta ?? {}) };
  let hint = typeof sanitized.hint === "string" ? sanitized.hint : undefined;

  const render = () => JSON.stringify({ ok: true, data, meta, ...(hint ? { hint } : {}) });

  let text = render();
  if (text.length > maxChars && Array.isArray(data)) {
    const rows = data as unknown[];
    const original = rows.length;
    // The truncation notes are part of the output, so set them before measuring.
    meta.truncated = true;
    hint = applyRedaction(truncationHint ?? "Output was cut to fit the size limit. Narrow the request or page with offset.");
    const take = (n: number) => {
      data = rows.slice(0, n);
      meta.count = n;
      meta.dropped_for_size = original - n;
      if (typeof meta.offset === "number") meta.next_offset = meta.offset + n;
    };
    // Binary search for the largest prefix that fits.
    let lo = 0;
    let hi = original;
    while (lo < hi) {
      const mid = Math.ceil((lo + hi) / 2);
      take(mid);
      if (render().length <= maxChars) lo = mid;
      else hi = mid - 1;
    }
    take(lo);
    text = render();
  } else if (text.length > maxChars && typeof data === "object" && data !== null) {
    // Single large object: shorten the longest string values.
    const obj = { ...(data as Record<string, unknown>) };
    const over = text.length - maxChars;
    const longest = Object.entries(obj)
      .filter(([, v]) => typeof v === "string")
      .sort(([, a], [, b]) => (b as string).length - (a as string).length)[0];
    if (longest) {
      const [k, v] = longest as [string, string];
      const keep = Math.max(0, v.length - over - 200);
      obj[k] = `${v.slice(0, keep)}… [cut, ${v.length - keep} more chars]`;
      data = obj;
      meta.truncated = true;
      hint = applyRedaction(truncationHint ?? "A long value was cut to fit the size limit.");
      text = render();
    }
  }
  return { content: [{ type: "text", text }] };
}

export function fail(err: unknown): CallToolResult {
  let body: Record<string, unknown>;
  if (err instanceof SplunkMcpError) {
    body = {
      ok: false,
      error: {
        code: err.code,
        message: err.message,
        ...(err.splunkMessages.length > 0 ? { splunk_messages: err.splunkMessages } : {}),
      },
      ...(err.meta ? { meta: err.meta } : {}),
      ...(err.hint ? { hint: err.hint } : {}),
    };
  } else {
    const message = err instanceof Error ? err.message : String(err);
    body = { ok: false, error: { code: "INTERNAL", message } };
  }
  const error = body.error as Record<string, unknown>;
  const { code, ...errorContent } = error;
  const sanitized = sanitizePayload({
    data: errorContent,
    meta: body.meta as Record<string, unknown> | undefined,
    hint: body.hint as string | undefined,
  });
  const safeBody = {
    ok: false,
    error: { code, ...(sanitized.data as Record<string, unknown>) },
    ...(body.meta ? { meta: sanitized.meta } : {}),
    ...(sanitized.hint ? { hint: sanitized.hint } : {}),
  };
  return { content: [{ type: "text", text: JSON.stringify(safeBody) }], isError: true };
}

/** Splunk epoch seconds (number or string) to ISO 8601; passes other values through. */
export function isoTime(v: unknown): unknown {
  const n = typeof v === "string" ? Number(v) : v;
  if (typeof n === "number" && Number.isFinite(n) && n > 0) return new Date(n * 1000).toISOString();
  return v ?? null;
}

export function contains(haystack: string, needle?: string): boolean {
  return !needle || haystack.toLowerCase().includes(needle.toLowerCase());
}
