import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { readFileSync } from "node:fs";
import type { Config, ConnectionConfig, EnvironmentConfig } from "./config.js";
import { log, normalizeFingerprint } from "./config.js";
import { decryptPassword } from "./crypto.js";
import { SplunkMcpError } from "./errors.js";

export interface RequestOptions {
  query?: Record<string, string | number | boolean | undefined | string[]>;
  form?: Record<string, string | number | boolean | undefined>;
  /** Do not add output_mode=json (KV store data endpoints return plain JSON). */
  rawJson?: boolean;
}

interface RawResponse {
  status: number;
  body: string;
}

/** Shared across all environments: the same AD password is used everywhere. */
export class LoginGate {
  private blocked = false;
  block(): void {
    this.blocked = true;
  }
  assertOpen(): void {
    if (this.blocked) {
      throw new SplunkMcpError(
        "LOGIN_BLOCKED",
        "Splunk rejected the login. Further logins are blocked to avoid locking the account.",
        {
          hint: "Do not retry. Tell the user to check the password (run `node dist/cli.js encrypt` again) and restart the MCP server.",
        },
      );
    }
  }
}

export interface PeerCertificateInfo {
  fingerprint256: string;
  subject: string;
  issuer: string;
  validFrom: string;
  validTo: string;
}

function nameOf(x: unknown): string {
  if (!x || typeof x !== "object") return "";
  return Object.entries(x as Record<string, unknown>)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(", ");
}

/** Connects once without verification and reports the certificate. Sends no data. */
export function fetchCertificate(host: string, port: number, timeoutMs = 10000): Promise<PeerCertificateInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout: timeoutMs });
    socket.once("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      socket.destroy();
      if (!cert || !cert.fingerprint256) {
        reject(new SplunkMcpError("TLS_ERROR", "The server did not present a certificate."));
        return;
      }
      resolve({
        fingerprint256: cert.fingerprint256,
        subject: nameOf(cert.subject),
        issuer: nameOf(cert.issuer),
        validFrom: cert.valid_from,
        validTo: cert.valid_to,
      });
    });
    socket.once("timeout", () => {
      socket.destroy();
      reject(new SplunkMcpError("UNREACHABLE", `Timed out connecting to ${host}:${port}.`));
    });
    socket.once("error", (err) => reject(err));
  });
}

/**
 * Agent for self-signed certificates: the TLS handshake is completed and the
 * certificate fingerprint compared BEFORE the socket is handed to the HTTP
 * layer, so no request (and no password) is ever written to an unknown peer.
 */
class PinnedAgent extends https.Agent {
  constructor(
    private readonly expected: string,
  ) {
    super({ keepAlive: true, maxSockets: 4 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  override createConnection(options: any, callback?: (err: Error | null, socket?: any) => void): any {
    const socket = tls.connect({
      host: options.host,
      port: Number(options.port),
      servername: options.servername ?? options.host,
      rejectUnauthorized: false,
    });
    let settled = false;
    const done = (err: Error | null) => {
      if (settled) return;
      settled = true;
      socket.removeListener("error", onError);
      if (err) {
        socket.destroy();
        callback?.(err);
      } else {
        callback?.(null, socket);
      }
    };
    const onError = (err: Error) => done(err);
    socket.once("error", onError);
    socket.once("secureConnect", () => {
      const actual = normalizeFingerprint(socket.getPeerCertificate()?.fingerprint256 ?? "");
      if (actual !== this.expected) {
        done(
          new SplunkMcpError(
            "TLS_FINGERPRINT_MISMATCH",
            "The Splunk certificate does not match the pinned fingerprint. Nothing was sent.",
            {
              hint: "Tell the user. If the certificate was replaced on purpose, run `node dist/cli.js fingerprint` and update SPLUNK_TLS_FINGERPRINT.",
            },
          ),
        );
        return;
      }
      done(null);
    });
    return undefined;
  }
}

function buildAgent(conn: ConnectionConfig): http.Agent | https.Agent {
  if (conn.url.startsWith("http://")) return new http.Agent({ keepAlive: true, maxSockets: 4 });
  switch (conn.tlsMode) {
    case "pinned": {
      if (!conn.tlsFingerprint) {
        throw new SplunkMcpError("TLS_FINGERPRINT_MISSING", "No certificate fingerprint configured.", {
          hint: `Tell the user to run \`node dist/cli.js fingerprint ${conn.url}\` and add SPLUNK_TLS_FINGERPRINT to settings.json (or set SPLUNK_TLS_MODE=insecure).`,
        });
      }
      return new PinnedAgent(conn.tlsFingerprint);
    }
    case "verify": {
      let ca: Buffer | undefined;
      if (conn.caCertPath) {
        try {
          ca = readFileSync(conn.caCertPath);
        } catch {
          throw new SplunkMcpError("CONFIG_ERROR", `Cannot read CA certificate file: ${conn.caCertPath}`);
        }
      }
      return new https.Agent({ keepAlive: true, maxSockets: 4, ca });
    }
    case "insecure":
      log("WARNING: the Splunk TLS certificate is not verified (SPLUNK_TLS_MODE=insecure).");
      return new https.Agent({ keepAlive: true, maxSockets: 4, rejectUnauthorized: false });
  }
}

function splunkMessages(body: string): string[] {
  try {
    const parsed = JSON.parse(body) as { messages?: Array<{ type?: string; text?: string }> };
    return (parsed.messages ?? []).map((m) => (m.type ? `${m.type}: ${m.text ?? ""}` : (m.text ?? ""))).filter(Boolean);
  } catch {
    return [];
  }
}

/** The one connection to Splunk: TLS, login and session. Shared by all environments. */
export class Connection {
  private agent?: http.Agent | https.Agent;
  private sessionKey?: string;
  private loginInFlight?: Promise<string>;
  private usernameCache?: string;
  sessionState: "none" | "active" | "failed" = "none";

  private readonly gate = new LoginGate();
  private readonly conn: ConnectionConfig;

  constructor(private readonly config: Config) {
    this.conn = config.connection;
  }

  private getAgent(): http.Agent | https.Agent {
    this.agent ??= buildAgent(this.conn);
    return this.agent;
  }

  private send(method: string, path: string, headers: Record<string, string>, body?: string): Promise<RawResponse> {
    const url = new URL(this.conn.url + path);
    const isHttps = url.protocol === "https:";
    const agent = this.getAgent();
    return new Promise<RawResponse>((resolve, reject) => {
      const req = (isHttps ? https : http).request(
        {
          method,
          host: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          agent,
          headers: {
            Accept: "application/json",
            ...(body !== undefined
              ? { "Content-Type": "application/x-www-form-urlencoded", "Content-Length": String(Buffer.byteLength(body)) }
              : {}),
            ...headers,
          },
          timeout: this.config.requestTimeoutMs,
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on("data", (c: Buffer) => chunks.push(c));
          res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
          res.on("error", reject);
        },
      );
      req.on("timeout", () => req.destroy(new SplunkMcpError("UNREACHABLE", "Request to Splunk timed out.")));
      req.on("error", (err) => reject(this.mapNetworkError(err)));
      if (body !== undefined) req.write(body);
      req.end();
    });
  }

  private mapNetworkError(err: unknown): Error {
    if (err instanceof SplunkMcpError) return err;
    const e = err as NodeJS.ErrnoException;
    const code = e.code ?? "";
    if (
      code.includes("CERT") ||
      code === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
      code === "SELF_SIGNED_CERT_IN_CHAIN" ||
      code === "UNABLE_TO_VERIFY_LEAF_SIGNATURE" ||
      code === "ERR_TLS_CERT_ALTNAME_INVALID"
    ) {
      return new SplunkMcpError("TLS_ERROR", `The Splunk TLS certificate is not trusted (${code}).`, {
        hint: "Set SPLUNK_TLS_MODE=pinned with SPLUNK_TLS_FINGERPRINT, or provide SPLUNK_CA_CERT.",
      });
    }
    return new SplunkMcpError(
      "UNREACHABLE",
      `Cannot reach Splunk at ${this.conn.url}${code ? ` (${code})` : ""}: ${e.message}`,
      { hint: "Check SPLUNK_URL, the port and VPN/network access. Do not retry in a loop." },
    );
  }

  private async login(): Promise<string> {
    if (this.config.token) return this.config.token;
    this.gate.assertOpen();
    const { username, passwordEnc, secret } = this.config;
    if (!username || !passwordEnc || !secret) {
      throw new SplunkMcpError("CONFIG_ERROR", "Credentials are not configured.");
    }
    const password = decryptPassword(passwordEnc, secret);
    const body = new URLSearchParams({ username, password, output_mode: "json" }).toString();
    const res = await this.send("POST", "/services/auth/login", {}, body);
    if (res.status === 200) {
      const key = (JSON.parse(res.body) as { sessionKey?: string }).sessionKey;
      if (key) {
        this.sessionState = "active";
        return key;
      }
    }
    this.sessionState = "failed";
    if (res.status === 401 || res.status === 403) {
      this.gate.block();
      throw new SplunkMcpError("AUTH_FAILED", "Splunk rejected the login.", {
        splunkMessages: splunkMessages(res.body),
        hint: "Do not retry. The password may be wrong, expired or the account locked. Tell the user to run `node dist/cli.js encrypt` again and restart the MCP server.",
      });
    }
    throw new SplunkMcpError("SPLUNK_ERROR", `Login failed with HTTP ${res.status}.`, {
      splunkMessages: splunkMessages(res.body),
    });
  }

  private async getSessionKey(): Promise<string> {
    if (this.sessionKey) return this.sessionKey;
    this.loginInFlight ??= this.login().finally(() => {
      this.loginInFlight = undefined;
    });
    this.sessionKey = await this.loginInFlight;
    return this.sessionKey;
  }

  private authHeader(key: string): Record<string, string> {
    return { Authorization: this.config.token ? `Bearer ${key}` : `Splunk ${key}` };
  }

  /** Performs a request and returns the raw response; re-authenticates once on 401. */
  private async sendAuthed(method: string, path: string, body?: string): Promise<RawResponse> {
    let key = await this.getSessionKey();
    let res = await this.send(method, path, this.authHeader(key), body);
    if (res.status === 401 && !this.config.token) {
      // Session expired: one fresh login, never more.
      this.sessionKey = undefined;
      key = await this.getSessionKey();
      res = await this.send(method, path, this.authHeader(key), body);
    }
    return res;
  }

  async request<T = unknown>(method: "GET" | "POST" | "DELETE", path: string, opts: RequestOptions = {}): Promise<T> {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(opts.query ?? {})) {
      if (v === undefined) continue;
      if (Array.isArray(v)) for (const item of v) params.append(k, item);
      else params.append(k, String(v));
    }
    let body: string | undefined;
    if (method === "GET" || method === "DELETE") {
      if (!opts.rawJson) params.set("output_mode", "json");
    } else {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(opts.form ?? {})) {
        if (v !== undefined) form.append(k, String(v));
      }
      form.set("output_mode", "json");
      body = form.toString();
    }
    const qs = params.toString();
    const fullPath = qs ? `${path}?${qs}` : path;

    const started = Date.now();
    const res = await this.sendAuthed(method, fullPath, body);
    if (this.config.debug) log(`${method} ${path} -> ${res.status} (${Date.now() - started} ms)`);

    if (res.status >= 200 && res.status < 300) {
      if (!res.body) return {} as T;
      try {
        return JSON.parse(res.body) as T;
      } catch {
        throw new SplunkMcpError("SPLUNK_ERROR", `Splunk returned a non-JSON response for ${path}.`);
      }
    }

    const messages = splunkMessages(res.body);
    const detail = messages.join(" | ") || `HTTP ${res.status}`;
    switch (res.status) {
      case 400:
        throw new SplunkMcpError("SPL_SYNTAX", `Splunk rejected the request: ${detail}`, {
          splunkMessages: messages,
          hint: "Read the Splunk message, fix the query or parameters and try again.",
        });
      case 401:
        throw new SplunkMcpError("AUTH_FAILED", `Not authenticated: ${detail}`, {
          splunkMessages: messages,
          hint: "Do not retry. Tell the user the credentials are not accepted.",
        });
      case 402:
      case 403:
        throw new SplunkMcpError("FORBIDDEN", `Not permitted: ${detail}`, {
          splunkMessages: messages,
          hint: "The user's Splunk role lacks a capability or index access. Call splunk_get_current_user to see the roles.",
        });
      case 404:
        throw new SplunkMcpError("NOT_FOUND", `Not found: ${detail}`, {
          splunkMessages: messages,
          hint: "Check the name (list the objects first). Job ids (sid) expire after a while.",
        });
      default:
        throw new SplunkMcpError("SPLUNK_ERROR", `Splunk error (HTTP ${res.status}): ${detail}`, {
          splunkMessages: messages,
        });
    }
  }

  get<T = unknown>(path: string, query?: RequestOptions["query"], rawJson = false): Promise<T> {
    return this.request<T>("GET", path, { query, rawJson });
  }

  post<T = unknown>(path: string, form?: RequestOptions["form"]): Promise<T> {
    return this.request<T>("POST", path, { form });
  }

  /** The Splunk user name, needed for the namespace of search jobs. */
  async username(): Promise<string> {
    if (this.usernameCache) return this.usernameCache;
    if (this.config.username && !this.config.token) {
      this.usernameCache = this.config.username;
      return this.usernameCache;
    }
    const ctx = await this.get<{ entry?: Array<{ content?: { username?: string } }> }>(
      "/services/authentication/current-context",
    );
    this.usernameCache = ctx.entry?.[0]?.content?.username ?? "nobody";
    return this.usernameCache;
  }

  close(): void {
    this.agent?.destroy();
  }
}

/** What a tool works with: the shared connection plus the chosen environment. */
export class SplunkClient {
  constructor(
    readonly env: EnvironmentConfig,
    private readonly connection: Connection,
  ) {}
  get<T = unknown>(path: string, query?: RequestOptions["query"], rawJson = false): Promise<T> {
    return this.connection.get<T>(path, query, rawJson);
  }
  post<T = unknown>(path: string, form?: RequestOptions["form"]): Promise<T> {
    return this.connection.post<T>(path, form);
  }
  username(): Promise<string> {
    return this.connection.username();
  }
}

export class ClientPool {
  readonly connection: Connection;
  private readonly clients = new Map<string, SplunkClient>();

  constructor(private readonly config: Config) {
    this.connection = new Connection(config);
  }

  get(environment: string): SplunkClient {
    const name = environment.trim().toUpperCase();
    const env = this.config.environments.get(name);
    if (!env) {
      throw new SplunkMcpError("UNKNOWN_ENVIRONMENT", `Environment "${environment}" is not configured.`, {
        hint: `Valid environments: ${[...this.config.environments.keys()].join(", ")}. Ask the user which one to use.`,
      });
    }
    let client = this.clients.get(name);
    if (!client) {
      client = new SplunkClient(env, this.connection);
      this.clients.set(name, client);
    }
    return client;
  }

  closeAll(): void {
    this.connection.close();
  }
}

export function enc(segment: string): string {
  return encodeURIComponent(segment);
}
