import type { EnvironmentConfig } from "./config.js";
import { SplunkMcpError } from "./errors.js";

export const RISKY_COMMANDS = new Set([
  "delete",
  "collect",
  "mcollect",
  "meventcollect",
  "outputlookup",
  "outputcsv",
  "sendemail",
  "sendalert",
  "script",
  "run",
  "runshellscript",
  "dump",
  "tscollect",
  "map",
  "dbxquery",
  "dbxoutput",
]);

/** Quote a value for use inside SPL: field="value". */
export function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Walks the query once and reports structure outside of quoted strings:
 * the commands in order (including those inside subsearches) and the
 * position of the first top-level pipe.
 */
export function scan(query: string): { commands: string[]; firstPipe: number } {
  const commands: string[] = [];
  let firstPipe = -1;
  let depth = 0;
  let inQuote = false;
  let expectCommand = true; // start of query is a command position

  for (let i = 0; i < query.length; i++) {
    const c = query[i]!;
    if (inQuote) {
      if (c === "\\") i++;
      else if (c === '"') inQuote = false;
      continue;
    }
    if (c === '"') {
      inQuote = true;
      expectCommand = false;
      continue;
    }
    if (c === "[") {
      depth++;
      expectCommand = true;
      continue;
    }
    if (c === "]") {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (c === "|") {
      if (depth === 0 && firstPipe === -1) firstPipe = i;
      expectCommand = true;
      continue;
    }
    if (expectCommand) {
      if (/\s/.test(c)) continue;
      const m = /^[A-Za-z_][A-Za-z0-9_]*/.exec(query.slice(i));
      if (m) {
        commands.push(m[0].toLowerCase());
        i += m[0].length - 1;
      }
      expectCommand = false;
    }
  }
  return { commands, firstPipe };
}

export function findRiskyCommands(query: string): string[] {
  const { commands } = scan(query);
  return [...new Set(commands.filter((c) => RISKY_COMMANDS.has(c)))];
}

/** Index names referenced as index=..., index!=..., index IN (...). */
export function findIndexes(query: string): string[] {
  const found = new Set<string>();
  const stripped = query;
  for (const m of stripped.matchAll(/\bindex\s*!?=\s*"?([A-Za-z0-9_*.\-]+)"?/gi)) found.add(m[1]!);
  for (const m of stripped.matchAll(/\bindex\s+IN\s*\(([^)]*)\)/gi)) {
    for (const part of m[1]!.split(",")) {
      const v = part.trim().replace(/^"|"$/g, "");
      if (v) found.add(v);
    }
  }
  return [...found];
}

export function guardQuery(query: string, env: EnvironmentConfig, allowRisky: boolean): void {
  if (!query.trim()) {
    throw new SplunkMcpError("INVALID_ARGUMENT", "The query is empty.");
  }
  if (!allowRisky) {
    const risky = findRiskyCommands(query);
    if (risky.length > 0) {
      throw new SplunkMcpError(
        "RISKY_SPL",
        `The query uses commands that are blocked on this server: ${risky.join(", ")}.`,
        { hint: "This server is read-only. Remove these commands and tell the user they are not available." },
      );
    }
  }
  if (env.allowedIndexes.length > 0) {
    const allowed = new Set(env.allowedIndexes.map((x) => x.toLowerCase()));
    const bad = findIndexes(query).filter((i) => !allowed.has(i.toLowerCase()));
    if (bad.length > 0) {
      throw new SplunkMcpError(
        "INDEX_NOT_ALLOWED",
        `Index not allowed in ${env.name}: ${bad.join(", ")}.`,
        { hint: `Allowed indexes: ${env.allowedIndexes.join(", ")}.` },
      );
    }
  }
}

export interface ScopeOptions {
  sourcetype?: string;
  host?: string;
  index?: string;
  ignoreDefaultScope?: boolean;
  includeExcluded?: boolean;
}

export interface ScopedQuery {
  query: string;
  scopeApplied: boolean;
  excluded: string[];
}

function hostClause(host: string): string {
  const parts = host
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean);
  if (parts.length > 1) return `host IN (${parts.map(quote).join(", ")})`;
  return `host=${quote(parts[0] ?? host)}`;
}

export function exclusionClauses(env: EnvironmentConfig): string[] {
  const out: string[] = [];
  if (env.excludeActuator) {
    out.push(env.actuatorField ? `NOT ${env.actuatorField}=${quote("/actuator*")}` : `NOT ${quote("/actuator")}`);
  }
  for (const term of env.excludeTerms) out.push(`NOT ${quote(term)}`);
  return out;
}

function mentions(base: string, field: string): boolean {
  return new RegExp(`\\b${field}\\s*(!?=|\\s+IN\\b)`, "i").test(base.replace(/"(?:\\.|[^"\\])*"/g, '""'));
}

/**
 * Puts the environment's default sourcetype/host/index and the exclusion
 * filters in front of the base search. Generating searches (starting with
 * a pipe) are returned unchanged.
 */
export function applyScope(rawQuery: string, env: EnvironmentConfig, opts: ScopeOptions = {}): ScopedQuery {
  const trimmed = rawQuery.trim();
  if (trimmed.startsWith("|")) {
    return { query: trimmed, scopeApplied: false, excluded: [] };
  }

  const body = trimmed.replace(/^search\b\s*/i, "");
  const { firstPipe } = scan(body);
  const base = firstPipe === -1 ? body : body.slice(0, firstPipe);
  const rest = firstPipe === -1 ? "" : body.slice(firstPipe);

  const prefix: string[] = [];
  const useDefaults = !opts.ignoreDefaultScope;

  const index = opts.index ?? (useDefaults ? env.defaultIndex : undefined);
  if (index && !mentions(base, "index")) prefix.push(`index=${quote(index)}`);

  const sourcetype = opts.sourcetype ?? (useDefaults ? env.defaultSourcetype : undefined);
  if (sourcetype && !mentions(base, "sourcetype")) prefix.push(`sourcetype=${quote(sourcetype)}`);

  const host = opts.host ?? (useDefaults ? env.defaultHost : undefined);
  if (host && !mentions(base, "host")) prefix.push(hostClause(host));

  const scopeApplied = prefix.length > 0;
  const excluded = opts.includeExcluded ? [] : exclusionClauses(env);

  // Filters go before the user's terms: OR binds tighter than the implicit
  // AND in SPL, so "a OR b" stays intact without extra parentheses.
  const parts = ["search", ...prefix, ...excluded, base.trim()].filter((p) => p.length > 0);
  if (parts.length === 1) parts.push("*");
  const query = `${parts.join(" ")}${rest ? ` ${rest.trim()}` : ""}`;
  return { query, scopeApplied, excluded };
}
