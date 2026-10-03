import { SplunkMcpError } from "./errors.js";
import { withConfigFiles } from "./files.js";
import { Redactor } from "./redact.js";

export type TlsMode = "pinned" | "verify" | "insecure";

export interface ConnectionConfig {
  /** Management API base URL without trailing slash, e.g. https://host:8089 */
  url: string;
  /** Splunk Web base URL, used only to build links. */
  webUrl: string;
  tlsMode: TlsMode;
  tlsFingerprint?: string;
  caCertPath?: string;
}

/** An environment is a host filter on the one Splunk instance. */
export interface EnvironmentConfig {
  name: string;
  /** Free text that tells the model what the environment is for. */
  description: string;
  /** Host patterns of this environment (exact names or wildcards). Never empty. */
  hosts: string[];
  /** Hosts that must never appear in results of this environment. */
  blockedHosts: string[];
  /** True if the environment contains a protected host (only possible with pseudonymisation). */
  isProtected: boolean;
  app: string;
  defaultSourcetype?: string;
  defaultIndex?: string;
  allowedIndexes: string[];
  excludeActuator: boolean;
  actuatorField?: string;
  excludeTerms: string[];
}

export interface Config {
  connection: ConnectionConfig;
  environments: Map<string, EnvironmentConfig>;
  /** Hosts whose data must never be returned (SPLUNK_BLOCKED_HOSTS). */
  blockedHosts: string[];
  /** Hosts that may only be searched while pseudonymisation is active (SPLUNK_PROTECTED_HOSTS). */
  protectedHosts: string[];
  /** Present if SPLUNK_REDACTION_FILE is set; pseudonymises every result. */
  redactor?: Redactor;
  username?: string;
  passwordEnc?: string;
  secret?: string;
  token?: string;
  locale: string;
  defaultEarliest: string;
  maxRows: number;
  maxOutputChars: number;
  searchTimeoutS: number;
  enableKvstore: boolean;
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

const HOST_PATTERN = /^[A-Za-z0-9_.\-*]+$/;

/** Case-insensitive glob match where * matches any run of characters. */
export function globMatch(pattern: string, value: string): boolean {
  const re = new RegExp(`^${pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*")}$`, "i");
  return re.test(value);
}

function hostList(raw: string | undefined, variable: string): string[] {
  const hosts = list(raw);
  for (const h of hosts) {
    if (!HOST_PATTERN.test(h)) {
      throw new SplunkMcpError("CONFIG_ERROR", `${variable} contains an invalid host name: "${h}".`);
    }
  }
  return hosts;
}

/**
 * Loads the configuration. When called for the real process environment, the
 * files in the project folder (.env, environments.json, redaction.json) are read too.
 */
export function loadConfig(rawEnv: Env = process.env, readFiles = rawEnv === process.env): Config {
  const env = readFiles ? withConfigFiles(rawEnv) : rawEnv;
  const allowHttp = bool(env.SPLUNK_ALLOW_HTTP, false);

  const rawUrl = clean(env.SPLUNK_URL);
  if (!rawUrl) {
    throw new SplunkMcpError("CONFIG_ERROR", "The Splunk address is not configured.", {
      hint: 'Create environments.json in the project folder (see environments.example.json) with "splunk": { "url": "https://splunk.example.lan:8089" }.',
    });
  }
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_URL is not a valid URL: "${rawUrl}".`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new SplunkMcpError("CONFIG_ERROR", "SPLUNK_URL must start with https:// or http://.");
  }
  if (parsed.protocol === "http:" && !allowHttp) {
    throw new SplunkMcpError("HTTP_NOT_ALLOWED", "SPLUNK_URL uses http://, which would send the password unencrypted.", {
      hint: "Use https:// or set SPLUNK_ALLOW_HTTP=true if you accept that.",
    });
  }
  const tlsModeRaw = (clean(env.SPLUNK_TLS_MODE) ?? "pinned").toLowerCase();
  if (tlsModeRaw !== "pinned" && tlsModeRaw !== "verify" && tlsModeRaw !== "insecure") {
    throw new SplunkMcpError("CONFIG_ERROR", "SPLUNK_TLS_MODE must be pinned, verify or insecure.");
  }
  const fp = clean(env.SPLUNK_TLS_FINGERPRINT);
  const connection: ConnectionConfig = {
    url: `${parsed.protocol}//${parsed.host}${parsed.pathname.replace(/\/+$/, "")}`,
    webUrl:
      clean(env.SPLUNK_WEB_URL)?.replace(/\/+$/, "") ??
      `${parsed.protocol}//${parsed.hostname}:${clean(env.SPLUNK_WEB_PORT) ?? "8443"}`,
    tlsMode: tlsModeRaw,
    tlsFingerprint: fp ? normalizeFingerprint(fp) : undefined,
    caCertPath: clean(env.SPLUNK_CA_CERT),
  };

  // Optional pseudonymisation. If the file is named but unusable, loading throws: fail closed.
  const redactionFile = clean(env.SPLUNK_REDACTION_FILE);
  const redactor = redactionFile ? Redactor.fromFile(redactionFile) : undefined;

  const blockedHosts = hostList(env.SPLUNK_BLOCKED_HOSTS, "SPLUNK_BLOCKED_HOSTS");
  const protectedHosts = hostList(env.SPLUNK_PROTECTED_HOSTS, "SPLUNK_PROTECTED_HOSTS");
  // The production host must be declared one way or the other: without it the protection would silently be off.
  if (blockedHosts.length === 0 && protectedHosts.length === 0) {
    throw new SplunkMcpError("CONFIG_ERROR", "Neither SPLUNK_BLOCKED_HOSTS nor SPLUNK_PROTECTED_HOSTS is set.", {
      hint: 'Name the production host(s) in environments.json: "blockedHosts" = never accessible; "protectedHosts" = accessible only with pseudonymisation (redaction.json).',
    });
  }
  if ([...blockedHosts, ...protectedHosts].some((h) => h.replace(/\*/g, "").length < 3)) {
    throw new SplunkMcpError("CONFIG_ERROR", "Entries in SPLUNK_BLOCKED_HOSTS / SPLUNK_PROTECTED_HOSTS must contain at least 3 literal characters.");
  }
  const overlaps = (a: string, b: string) =>
    globMatch(a, b) || globMatch(b, a) || globMatch(a, b.replace(/\*/g, "")) || globMatch(b, a.replace(/\*/g, ""));

  const environments = new Map<string, EnvironmentConfig>();
  for (const [key, raw] of Object.entries(env)) {
    const m = /^SPLUNK_HOST_([A-Z0-9]+)$/.exec(key);
    if (!m || !clean(raw)) continue;
    const name = m[1]!;
    const hosts = hostList(raw, key);
    for (const h of hosts) {
      if (h.replace(/\*/g, "") === "") {
        throw new SplunkMcpError("CONFIG_ERROR", `${key} must not be a bare wildcard.`);
      }
      if (blockedHosts.some((b) => overlaps(h, b))) {
        throw new SplunkMcpError(
          "CONFIG_ERROR",
          `${key} ("${h}") overlaps with a blocked host in SPLUNK_BLOCKED_HOSTS. Refusing to start.`,
        );
      }
    }
    const touched = protectedHosts.filter((p) => hosts.some((h) => overlaps(h, p)));
    if (touched.length > 0 && !redactor) {
      throw new SplunkMcpError(
        "CONFIG_ERROR",
        `${key} contains a protected host (SPLUNK_PROTECTED_HOSTS), but pseudonymisation is not configured. Refusing to start.`,
        { hint: "Set SPLUNK_REDACTION_FILE, or remove this environment." },
      );
    }
    environments.set(name, {
      name,
      description: clean(env[`SPLUNK_DESCRIPTION_${name}`]) ?? "",
      hosts,
      // Protected hosts that do not belong to this environment are blocked in it.
      blockedHosts: [...blockedHosts, ...protectedHosts.filter((p) => !touched.includes(p))],
      isProtected: touched.length > 0,
      app: scoped(env, "SPLUNK_APP", name) ?? "search",
      defaultSourcetype: scoped(env, "SPLUNK_SOURCETYPE", name),
      defaultIndex: scoped(env, "SPLUNK_INDEX", name),
      allowedIndexes: list(scoped(env, "SPLUNK_ALLOWED_INDEXES", name)),
      excludeActuator: bool(scoped(env, "SPLUNK_EXCLUDE_ACTUATOR", name), false),
      actuatorField: scoped(env, "SPLUNK_ACTUATOR_FIELD", name),
      excludeTerms: list(scoped(env, "SPLUNK_EXCLUDE_TERMS", name)),
    });
  }

  if (environments.size === 0) {
    throw new SplunkMcpError("CONFIG_ERROR", "No environment configured.", {
      hint: 'Add at least one entry under "environments" in environments.json, e.g. "INT1": { "hosts": ["inthost01"] }.',
    });
  }

  const token = clean(env.SPLUNK_TOKEN);
  const username = clean(env.SPLUNK_USERNAME);
  const passwordEnc = clean(env.SPLUNK_PASSWORD_ENC);
  const secret = clean(env.SPLUNK_SECRET);

  if (clean(env.SPLUNK_PASSWORD)) {
    throw new SplunkMcpError(
      "CONFIG_ERROR",
      "SPLUNK_PASSWORD (plain text) is not supported.",
      { hint: "Run `node dist/cli.js encrypt --write`; it stores SPLUNK_PASSWORD_ENC and SPLUNK_SECRET in .env." },
    );
  }
  if (!token && !(username && passwordEnc && secret)) {
    throw new SplunkMcpError(
      "CONFIG_ERROR",
      'Credentials missing: "splunk.user" in environments.json plus SPLUNK_PASSWORD_ENC and SPLUNK_SECRET in .env.',
      { hint: "Run `node dist/cli.js encrypt --write` to store the encrypted password in .env." },
    );
  }

  // Keep environments in a stable, readable order.
  const sorted = new Map([...environments.entries()].sort(([a], [b]) => a.localeCompare(b)));

  return {
    connection,
    environments: sorted,
    blockedHosts,
    protectedHosts,
    redactor,
    username,
    passwordEnc,
    secret,
    token,
    locale: clean(env.SPLUNK_LOCALE) ?? "de-DE",
    defaultEarliest: clean(env.SPLUNK_DEFAULT_EARLIEST) ?? "-24h",
    maxRows: int(env.SPLUNK_MAX_ROWS, 1000, "SPLUNK_MAX_ROWS"),
    maxOutputChars: int(env.SPLUNK_MAX_OUTPUT_CHARS, 40000, "SPLUNK_MAX_OUTPUT_CHARS"),
    searchTimeoutS: int(env.SPLUNK_SEARCH_TIMEOUT_S, 120, "SPLUNK_SEARCH_TIMEOUT_S"),
    enableKvstore: bool(env.SPLUNK_ENABLE_KVSTORE, false),
    allowHttp,
    requestTimeoutMs: int(env.SPLUNK_REQUEST_TIMEOUT_MS, 60000, "SPLUNK_REQUEST_TIMEOUT_MS"),
    debug: bool(env.SPLUNK_DEBUG, false),
  };
}

export function log(...args: unknown[]): void {
  // stdout belongs to the MCP protocol; everything else goes to stderr.
  console.error("[splunk-mcp]", ...args);
}
