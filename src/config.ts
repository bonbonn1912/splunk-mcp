import { SplunkMcpError } from "./errors.js";

export type TlsMode = "pinned" | "verify" | "insecure";

export interface EnvironmentConfig {
  name: string;
  /** Management API base URL without trailing slash, e.g. https://host:8089 */
  url: string;
  /** Splunk Web base URL, used only to build links. */
  webUrl: string;
  app: string;
  tlsMode: TlsMode;
  tlsFingerprint?: string;
  caCertPath?: string;
  defaultSourcetype?: string;
  defaultHost?: string;
  defaultIndex?: string;
  allowedIndexes: string[];
  excludeActuator: boolean;
  actuatorField?: string;
  excludeTerms: string[];
}

export interface Config {
  environments: Map<string, EnvironmentConfig>;
  username?: string;
  passwordEnc?: string;
  secret?: string;
  token?: string;
  locale: string;
  defaultEarliest: string;
  maxRows: number;
  maxOutputChars: number;
  searchTimeoutS: number;
  allowRiskySpl: boolean;
  allowHttp: boolean;
  requestTimeoutMs: number;
  debug: boolean;
}

type Env = Record<string, string | undefined>;

function clean(v: string | undefined): string | undefined {
  const t = v?.trim();
  return t ? t : undefined;
}

function bool(v: string | undefined, fallback: boolean): boolean {
  const t = clean(v)?.toLowerCase();
  if (t === undefined) return fallback;
  return t === "true" || t === "1" || t === "yes";
}

function int(v: string | undefined, fallback: number, name: string): number {
  const t = clean(v);
  if (t === undefined) return fallback;
  const n = Number(t);
  if (!Number.isInteger(n) || n <= 0) {
    throw new SplunkMcpError("CONFIG_ERROR", `${name} must be a positive integer, got "${t}".`);
  }
  return n;
}

function list(v: string | undefined): string[] {
  return (clean(v) ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
}

/** Per-environment value (<VAR>_<NAME>) wins over the global one (<VAR>). */
function scoped(env: Env, variable: string, name: string): string | undefined {
  return clean(env[`${variable}_${name}`]) ?? clean(env[variable]);
}

export function normalizeFingerprint(fp: string): string {
  return fp.replace(/[^0-9a-fA-F]/g, "").toUpperCase();
}

export function loadConfig(env: Env = process.env): Config {
  const environments = new Map<string, EnvironmentConfig>();
  const allowHttp = bool(env.SPLUNK_ALLOW_HTTP, false);
  const webPort = clean(env.SPLUNK_WEB_PORT) ?? "8443";

  for (const [key, raw] of Object.entries(env)) {
    const m = /^SPLUNK_URL_([A-Z0-9]+)$/.exec(key);
    const value = clean(raw);
    if (!m || !value) continue;
    const name = m[1]!;

    let parsed: URL;
    try {
      parsed = new URL(value);
    } catch {
      throw new SplunkMcpError("CONFIG_ERROR", `${key} is not a valid URL: "${value}".`);
    }
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
      throw new SplunkMcpError("CONFIG_ERROR", `${key} must start with https:// or http://.`);
    }
    if (parsed.protocol === "http:" && !allowHttp) {
      throw new SplunkMcpError(
        "HTTP_NOT_ALLOWED",
        `${key} uses http://, which would send the password unencrypted.`,
        { hint: "Use https:// or set SPLUNK_ALLOW_HTTP=true if you accept that." },
      );
    }

    const tlsModeRaw = (scoped(env, "SPLUNK_TLS_MODE", name) ?? "pinned").toLowerCase();
    if (tlsModeRaw !== "pinned" && tlsModeRaw !== "verify" && tlsModeRaw !== "insecure") {
      throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_TLS_MODE for ${name} must be pinned, verify or insecure.`);
    }

    const fp = clean(env[`SPLUNK_TLS_FINGERPRINT_${name}`]);
    const webUrl =
      clean(env[`SPLUNK_WEB_URL_${name}`])?.replace(/\/+$/, "") ??
      `${parsed.protocol}//${parsed.hostname}:${webPort}`;

    environments.set(name, {
      name,
      url: `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, "")}`,
      webUrl,
      app: scoped(env, "SPLUNK_APP", name) ?? "search",
      tlsMode: tlsModeRaw,
      tlsFingerprint: fp ? normalizeFingerprint(fp) : undefined,
      caCertPath: scoped(env, "SPLUNK_CA_CERT", name),
      defaultSourcetype: clean(env[`SPLUNK_SOURCETYPE_${name}`]),
      defaultHost: clean(env[`SPLUNK_HOST_${name}`]),
      defaultIndex: clean(env[`SPLUNK_INDEX_${name}`]),
      allowedIndexes: list(scoped(env, "SPLUNK_ALLOWED_INDEXES", name)),
      excludeActuator: bool(scoped(env, "SPLUNK_EXCLUDE_ACTUATOR", name), false),
      actuatorField: scoped(env, "SPLUNK_ACTUATOR_FIELD", name),
      excludeTerms: list(scoped(env, "SPLUNK_EXCLUDE_TERMS", name)),
    });
  }

  if (environments.size === 0) {
    throw new SplunkMcpError(
      "CONFIG_ERROR",
      "No Splunk environment configured.",
      { hint: "Set at least one SPLUNK_URL_<NAME>, e.g. SPLUNK_URL_TEST=https://splunk-test.example.lan:8089" },
    );
  }

  const token = clean(env.SPLUNK_TOKEN);
  const username = clean(env.SPLUNK_USERNAME);
  const passwordEnc = clean(env.SPLUNK_PASSWORD_ENC);
  const secret = clean(env.SPLUNK_SECRET);

  if (clean(env.SPLUNK_PASSWORD)) {
    throw new SplunkMcpError(
      "CONFIG_ERROR",
      "SPLUNK_PASSWORD (plain text) is not supported.",
      { hint: "Run `node dist/cli.js encrypt` and set SPLUNK_PASSWORD_ENC and SPLUNK_SECRET instead." },
    );
  }
  if (!token && !(username && passwordEnc && secret)) {
    throw new SplunkMcpError(
      "CONFIG_ERROR",
      "Credentials missing: set SPLUNK_USERNAME, SPLUNK_PASSWORD_ENC and SPLUNK_SECRET (or SPLUNK_TOKEN).",
      { hint: "Run `node dist/cli.js encrypt` to create SPLUNK_PASSWORD_ENC and SPLUNK_SECRET." },
    );
  }

  // Keep environments in a stable, readable order.
  const sorted = new Map([...environments.entries()].sort(([a], [b]) => a.localeCompare(b)));

  return {
    environments: sorted,
    username,
    passwordEnc,
    secret,
    token,
    locale: clean(env.SPLUNK_LOCALE) ?? "de-DE",
    defaultEarliest: clean(env.SPLUNK_DEFAULT_EARLIEST) ?? "-24h",
    maxRows: int(env.SPLUNK_MAX_ROWS, 1000, "SPLUNK_MAX_ROWS"),
    maxOutputChars: int(env.SPLUNK_MAX_OUTPUT_CHARS, 40000, "SPLUNK_MAX_OUTPUT_CHARS"),
    searchTimeoutS: int(env.SPLUNK_SEARCH_TIMEOUT_S, 120, "SPLUNK_SEARCH_TIMEOUT_S"),
    allowRiskySpl: bool(env.SPLUNK_ALLOW_RISKY_SPL, false),
    allowHttp,
    requestTimeoutMs: int(env.SPLUNK_REQUEST_TIMEOUT_MS, 60000, "SPLUNK_REQUEST_TIMEOUT_MS"),
    debug: bool(env.SPLUNK_DEBUG, false),
  };
}

export function log(...args: unknown[]): void {
  // stdout belongs to the MCP protocol; everything else goes to stderr.
  console.error("[splunk-mcp]", ...args);
}
