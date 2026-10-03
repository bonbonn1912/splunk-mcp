/**
 * Configuration files in the project folder (next to dist/), same layout as oracle-mcp:
 *
 *   environments.json   Splunk address, hosts of every environment, blocked hosts, defaults
 *   .env                the (encrypted) password
 *   redaction.json      optional pseudonymisation rules
 *
 * Both files are translated into the SPLUNK_* variables that config.ts understands.
 * Real environment variables (e.g. the env block of the Gemini settings.json) win over .env;
 * environments.json wins over both.
 */
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { SplunkMcpError } from "./errors.js";

type Env = Record<string, string | undefined>;

export function projectRoot(): string {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

export function dotEnvPath(env: Env = process.env): string {
  return path.resolve(projectRoot(), env.SPLUNK_ENV_FILE?.trim() || ".env");
}

export function environmentsFilePath(env: Env = process.env): string {
  return path.resolve(projectRoot(), env.SPLUNK_ENVIRONMENTS_FILE?.trim() || "environments.json");
}

/** Gemini leaves "${VAR}" untouched when VAR is not set; treat that as "not set". */
function isSet(v: string | undefined): boolean {
  if (v === undefined) return false;
  const t = v.trim();
  return t !== "" && !/^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$/.test(t);
}

/** Reads KEY=VALUE lines. Values already set in the environment win. */
export function parseDotEnv(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#")) continue;
    const m = /^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/.exec(line);
    if (!m) continue;
    let value = m[2]!.trim();
    const quoted = /^(["'])(.*)\1$/.exec(value);
    if (quoted) value = quoted[2]!;
    else value = value.replace(/\s+#.*$/, "");
    out[m[1]!] = value;
  }
  return out;
}

const SPLUNK_KEYS: Record<string, string> = {
  url: "SPLUNK_URL",
  user: "SPLUNK_USERNAME",
  tlsMode: "SPLUNK_TLS_MODE",
  tlsFingerprint: "SPLUNK_TLS_FINGERPRINT",
  caCert: "SPLUNK_CA_CERT",
  allowHttp: "SPLUNK_ALLOW_HTTP",
  webUrl: "SPLUNK_WEB_URL",
  webPort: "SPLUNK_WEB_PORT",
  locale: "SPLUNK_LOCALE",
};

/** Usable at the top level (default for all environments) and inside one environment. */
const SCOPED_KEYS: Record<string, string> = {
  app: "SPLUNK_APP",
  sourcetype: "SPLUNK_SOURCETYPE",
  index: "SPLUNK_INDEX",
  allowedIndexes: "SPLUNK_ALLOWED_INDEXES",
  excludeActuator: "SPLUNK_EXCLUDE_ACTUATOR",
  actuatorField: "SPLUNK_ACTUATOR_FIELD",
  excludeTerms: "SPLUNK_EXCLUDE_TERMS",
};

const TOP_KEYS: Record<string, string> = {
  blockedHosts: "SPLUNK_BLOCKED_HOSTS",
  protectedHosts: "SPLUNK_PROTECTED_HOSTS",
  redactionFile: "SPLUNK_REDACTION_FILE",
  enableKvstore: "SPLUNK_ENABLE_KVSTORE",
  defaultEarliest: "SPLUNK_DEFAULT_EARLIEST",
  maxRows: "SPLUNK_MAX_ROWS",
  maxOutputChars: "SPLUNK_MAX_OUTPUT_CHARS",
  searchTimeoutS: "SPLUNK_SEARCH_TIMEOUT_S",
};

function scalar(v: unknown, what: string): string {
  if (Array.isArray(v)) {
    if (v.some((x) => typeof x !== "string" && typeof x !== "number")) {
      throw new SplunkMcpError("CONFIG_ERROR", `${what}: list entries must be text.`);
    }
    return v.map(String).join(",");
  }
  if (typeof v === "string" || typeof v === "number" || typeof v === "boolean") return String(v);
  throw new SplunkMcpError("CONFIG_ERROR", `${what}: must be text, a number, true/false or a list.`);
}

function object(v: unknown, what: string): Record<string, unknown> {
  if (!v || typeof v !== "object" || Array.isArray(v)) {
    throw new SplunkMcpError("CONFIG_ERROR", `${what}: must be an object { ... }.`);
  }
  return v as Record<string, unknown>;
}

/** Translates environments.json into SPLUNK_* variables. Unknown keys are an error (typos must not go unnoticed). */
export function translateEnvironmentsFile(parsed: unknown, fileName: string): Record<string, string> {
  const out: Record<string, string> = {};
  const root = object(parsed, fileName);
  const unknown = (key: string, where: string, allowed: string[]) =>
    new SplunkMcpError("CONFIG_ERROR", `${fileName}: unknown entry "${key}" in ${where}.`, {
      hint: `Allowed: ${allowed.join(", ")}.`,
    });

  for (const [key, value] of Object.entries(root)) {
    if (key.startsWith("//") || key === "$comment") continue;
    if (value === null || value === undefined) continue;
    if (key === "splunk") {
      for (const [k, v] of Object.entries(object(value, `${fileName} → "splunk"`))) {
        if (v === null || v === undefined) continue;
        const target = SPLUNK_KEYS[k];
        if (!target) throw unknown(k, '"splunk"', Object.keys(SPLUNK_KEYS));
        out[target] = scalar(v, `${fileName} → splunk.${k}`);
      }
    } else if (key === "environments") {
      for (const [rawName, rawEntry] of Object.entries(object(value, `${fileName} → "environments"`))) {
        const name = rawName.trim().toUpperCase();
        const what = `${fileName} → "${rawName}"`;
        if (!/^[A-Z0-9]{1,40}$/.test(name)) {
          throw new SplunkMcpError("CONFIG_ERROR", `${what}: environment names may only contain letters and digits (max 40).`);
        }
        if (out[`SPLUNK_HOST_${name}`] !== undefined) {
          throw new SplunkMcpError("CONFIG_ERROR", `${what}: duplicate environment name.`);
        }
        const entry = object(rawEntry, what);
        if (entry.hosts === undefined || entry.hosts === null || scalar(entry.hosts, `${what}.hosts`).trim() === "") {
          throw new SplunkMcpError("CONFIG_ERROR", `${what}: "hosts" is required.`);
        }
        for (const [k, v] of Object.entries(entry)) {
          if (v === null || v === undefined) continue;
          if (k === "hosts") out[`SPLUNK_HOST_${name}`] = scalar(v, `${what}.hosts`);
          else if (k === "description") out[`SPLUNK_DESCRIPTION_${name}`] = scalar(v, `${what}.description`);
          else if (SCOPED_KEYS[k]) out[`${SCOPED_KEYS[k]}_${name}`] = scalar(v, `${what}.${k}`);
          else throw unknown(k, `environment "${rawName}"`, ["hosts", "description", ...Object.keys(SCOPED_KEYS)]);
        }
      }
    } else if (TOP_KEYS[key]) {
      out[TOP_KEYS[key]!] = scalar(value, `${fileName} → ${key}`);
    } else if (SCOPED_KEYS[key]) {
      out[SCOPED_KEYS[key]!] = scalar(value, `${fileName} → ${key}`);
    } else {
      throw unknown(key, "the top level", ["splunk", "environments", ...Object.keys(TOP_KEYS), ...Object.keys(SCOPED_KEYS)]);
    }
  }
  return out;
}

/**
 * Returns the effective variables: process environment, completed from .env,
 * overlaid with environments.json. Does not modify process.env.
 */
export function withConfigFiles(env: Env): Env {
  const merged: Env = { ...env };
  // Unresolved "${VAR}" placeholders count as not set.
  for (const [k, v] of Object.entries(merged)) if (!isSet(v)) delete merged[k];

  const envFile = dotEnvPath(env);
  if (existsSync(envFile)) {
    for (const [k, v] of Object.entries(parseDotEnv(readFileSync(envFile, "utf8")))) {
      if (merged[k] === undefined) merged[k] = v;
    }
  } else if (isSet(env.SPLUNK_ENV_FILE)) {
    throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_ENV_FILE not found: ${envFile}`);
  }

  const file = environmentsFilePath(env);
  if (existsSync(file)) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      throw new SplunkMcpError("CONFIG_ERROR", `${file} is not valid JSON: ${(e as Error).message}`);
    }
    Object.assign(merged, translateEnvironmentsFile(parsed, path.basename(file)));
  } else if (isSet(env.SPLUNK_ENVIRONMENTS_FILE)) {
    throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_ENVIRONMENTS_FILE not found: ${file}`);
  }

  // Pseudonymisation: a path from the configuration, or redaction.json in the project folder if it exists.
  if (merged.SPLUNK_REDACTION_FILE) {
    merged.SPLUNK_REDACTION_FILE = path.resolve(projectRoot(), merged.SPLUNK_REDACTION_FILE);
  } else {
    const auto = path.resolve(projectRoot(), "redaction.json");
    if (existsSync(auto)) merged.SPLUNK_REDACTION_FILE = auto;
  }
  if (merged.SPLUNK_CA_CERT) merged.SPLUNK_CA_CERT = path.resolve(projectRoot(), merged.SPLUNK_CA_CERT);
  return merged;
}
