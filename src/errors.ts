export type ErrorCode =
  | "AUTH_FAILED"
  | "LOGIN_BLOCKED"
  | "DECRYPT_FAILED"
  | "FORBIDDEN"
  | "NOT_FOUND"
  | "SPL_SYNTAX"
  | "QUERY_NOT_ALLOWED"
  | "BLOCKED_HOST"
  | "UNKNOWN_SID"
  | "INDEX_NOT_ALLOWED"
  | "JOB_NOT_DONE"
  | "JOB_FAILED"
  | "TIMEOUT"
  | "TLS_ERROR"
  | "TLS_FINGERPRINT_MISSING"
  | "TLS_FINGERPRINT_MISMATCH"
  | "HTTP_NOT_ALLOWED"
  | "UNREACHABLE"
  | "UNKNOWN_ENVIRONMENT"
  | "INVALID_ARGUMENT"
  | "CONFIG_ERROR"
  | "SPLUNK_ERROR";

export class SplunkMcpError extends Error {
  readonly code: ErrorCode;
  readonly hint?: string;
  readonly splunkMessages: string[];
  readonly meta?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string,
    opts: { hint?: string; splunkMessages?: string[]; meta?: Record<string, unknown> } = {},
  ) {
    super(message);
    this.name = "SplunkMcpError";
    this.code = code;
    this.hint = opts.hint;
    this.splunkMessages = opts.splunkMessages ?? [];
    this.meta = opts.meta;
  }
}
