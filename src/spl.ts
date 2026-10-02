import { globMatch, type EnvironmentConfig } from "./config.js";
import { SplunkMcpError } from "./errors.js";

/**
 * Only these commands may follow the base search. They transform or filter the
 * events already selected; none of them can pull in events from elsewhere.
 * Anything not listed (append, join, union, tstats, inputlookup, loadjob, map,
 * delete, collect, outputlookup, sendemail, custom commands, ...) is rejected.
 */
export const ALLOWED_COMMANDS = new Set([
  "search", "where", "regex", "eval", "rex", "erex", "spath", "xpath", "extract", "kv", "xmlkv", "multikv",
  "stats", "eventstats", "streamstats", "timechart", "chart", "top", "rare", "contingency",
  "table", "fields", "rename", "sort", "reverse", "head", "tail", "dedup", "uniq",
  "bin", "bucket", "timewrap", "makecontinuous", "fillnull", "filldown", "replace", "convert", "fieldformat",
  "mvexpand", "mvcombine", "makemv", "nomv", "strcat", "rangemap", "addinfo",
  "transaction", "cluster", "addtotals", "addcoltotals", "accum", "delta", "autoregress", "trendline",
  "untable", "xyseries", "transpose", "fieldsummary", "lookup", "iplocation",
  "abstract", "highlight", "outlier", "anomalydetection", "scrub", "tags", "typer",
]);

/** Quote a value for use inside SPL: field="value". */
export function quote(value: string): string {
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

export interface Structure {
  /** Positions of pipes outside quoted strings. */
  pipes: number[];
  /** Command name following each pipe (lower case, "" if none found). */
  pipeCommands: string[];
  hasBracket: boolean;
  unbalancedQuote: boolean;
  /** Parentheses outside quotes are balanced in every pipeline segment. */
  parensBalanced: boolean;
}

/** Walks the query once and reports its structure outside of quoted strings. */
export function scan(query: string): Structure {
  const pipes: number[] = [];
  const pipeCommands: string[] = [];
  let hasBracket = false;
  let inQuote = false;
  let depth = 0;
  let parensBalanced = true;

  for (let i = 0; i < query.length; i++) {
    const c = query[i]!;
    if (inQuote) {
      if (c === "\\") i++;
      else if (c === '"') inQuote = false;
      continue;
    }
    if (c === '"') inQuote = true;
    else if (c === "[" || c === "]") hasBracket = true;
    else if (c === "(") depth++;
    else if (c === ")") {
      depth--;
      if (depth < 0) parensBalanced = false;
    } else if (c === "|") {
      if (depth !== 0) parensBalanced = false;
      depth = 0;
      pipes.push(i);
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)?/.exec(query.slice(i + 1));
      pipeCommands.push((m?.[1] ?? "").toLowerCase());
    }
  }
  if (depth !== 0) parensBalanced = false;
  return { pipes, pipeCommands, hasBracket, unbalancedQuote: inQuote, parensBalanced };
}

/** Index names referenced as index=..., index!=..., index IN (...). */
export function findIndexes(query: string): string[] {
  const found = new Set<string>();
  for (const m of query.matchAll(/\bindex\s*!?=\s*"?([A-Za-z0-9_*.\-]+)"?/gi)) found.add(m[1]!);
  for (const m of query.matchAll(/\bindex\s+IN\s*\(([^)]*)\)/gi)) {
    for (const part of m[1]!.split(",")) {
      const v = part.trim().replace(/^"|"$/g, "");
      if (v) found.add(v);
    }
  }
  return [...found];
}

/** True if the text contains the name of a blocked host (case-insensitive, wildcards honoured). */
export function mentionsBlockedHost(text: string, blockedHosts: string[]): boolean {
  const lower = text.toLowerCase();
  return blockedHosts.some((b) => {
    if (!b.includes("*")) return lower.includes(b.toLowerCase());
    const re = new RegExp(
      b
        .split("*")
        .map((part) => part.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
        .join("[A-Za-z0-9_.\\-]*"),
      "i",
    );
    return re.test(text);
  });
}

export function isBlockedHost(host: string, blockedHosts: string[]): boolean {
  return blockedHosts.some((b) => globMatch(b, host.trim()));
}

function notAllowed(message: string, hint: string): SplunkMcpError {
  return new SplunkMcpError("QUERY_NOT_ALLOWED", message, { hint });
}

/**
 * Checks a query written by the model (or stored in a saved search) BEFORE the
 * environment's host filter is put in front of it. The rules make sure that
 * the mandatory host filter cannot be bypassed:
 *  - it must be an event search (no leading pipe / generating command),
 *  - no subsearches and no macros (both can smuggle in other searches),
 *  - only whitelisted commands after the base search,
 *  - balanced quotes and parentheses (so the filter cannot be "closed" early),
 *  - no mention of a blocked host.
 */
export function validateQuery(query: string, env: EnvironmentConfig, blockedHosts: string[]): void {
  const trimmed = query.trim();
  if (!trimmed) throw new SplunkMcpError("INVALID_ARGUMENT", "The query is empty.");

  if (mentionsBlockedHost(trimmed, blockedHosts)) {
    throw new SplunkMcpError("BLOCKED_HOST", "The query refers to a host that is blocked on this server.", {
      hint: "Data from this host must never be accessed. Do not try other ways to reach it. Tell the user.",
    });
  }
  if (trimmed.startsWith("|")) {
    throw notAllowed(
      "Queries starting with a pipe (generating commands such as tstats, metadata, inputlookup, loadjob, rest) are not allowed.",
      "Write an event search: search terms first, then pipes, e.g. `level=ERROR | stats count by logger`. The environment's host filter is added automatically.",
    );
  }
  if (trimmed.includes("`")) {
    throw notAllowed("Macros and backticks are not allowed.", "Write the search without macros.");
  }
  const s = scan(trimmed);
  if (s.unbalancedQuote) {
    throw notAllowed("The query has an unbalanced double quote.", "Close every quoted string.");
  }
  if (s.hasBracket) {
    throw notAllowed(
      "Subsearches and square brackets are not allowed (append, join, union, foreach and similar cannot be used).",
      "Rewrite the query as a single search with stats/eval. If a regular expression needs [ or ], put it inside double quotes.",
    );
  }
  if (!s.parensBalanced) {
    throw notAllowed("Parentheses are not balanced.", "Balance the parentheses within each part of the pipeline.");
  }
  const bad = [...new Set(s.pipeCommands.filter((c) => !ALLOWED_COMMANDS.has(c)))];
  if (bad.length > 0) {
    throw notAllowed(
      `Command not allowed: ${bad.map((c) => c || "(empty)").join(", ")}.`,
      `Only these commands may follow the base search: ${[...ALLOWED_COMMANDS].join(", ")}.`,
    );
  }
  if (env.allowedIndexes.length > 0) {
    const allowed = new Set(env.allowedIndexes.map((x) => x.toLowerCase()));
    const wrong = findIndexes(trimmed).filter((i) => !allowed.has(i.toLowerCase()));
    if (wrong.length > 0) {
      throw new SplunkMcpError("INDEX_NOT_ALLOWED", `Index not allowed in ${env.name}: ${wrong.join(", ")}.`, {
        hint: `Allowed indexes: ${env.allowedIndexes.join(", ")}.`,
      });
    }
  }
}

export function hostClause(hosts: string[]): string {
  if (hosts.length === 1) return `host=${quote(hosts[0]!)}`;
  return `host IN (${hosts.map(quote).join(", ")})`;
}

export function blockedClause(blockedHosts: string[]): string {
  return blockedHosts.map((b) => `NOT host=${quote(b)}`).join(" ");
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

export interface ScopeOptions {
  sourcetype?: string;
  index?: string;
  includeExcluded?: boolean;
}

export interface ScopedQuery {
  query: string;
  excluded: string[];
}

/**
 * Builds the query that is actually sent to Splunk:
 *
 *   search [index] [sourcetype] <host of the environment> NOT host=<blocked> [exclusions] ( <user terms> ) | <user pipeline>
 *
 * The host filter and the blocked-host filter are ALWAYS present and cannot be
 * switched off. The user's terms are wrapped in parentheses so that an OR in
 * them cannot widen the host filter. Call validateQuery() first.
 */
export function applyScope(
  rawQuery: string,
  env: EnvironmentConfig,
  blockedHosts: string[],
  opts: ScopeOptions = {},
): ScopedQuery {
  const body = rawQuery.trim().replace(/^search\b\s*/i, "");
  const firstPipe = scan(body).pipes[0] ?? -1;
  const base = (firstPipe === -1 ? body : body.slice(0, firstPipe)).trim();
  const rest = firstPipe === -1 ? "" : body.slice(firstPipe).trim();

  const prefix: string[] = [];
  const index = opts.index ?? env.defaultIndex;
  if (index && !mentions(base, "index")) prefix.push(`index=${quote(index)}`);
  const sourcetype = opts.sourcetype ?? env.defaultSourcetype;
  if (sourcetype && !mentions(base, "sourcetype")) prefix.push(`sourcetype=${quote(sourcetype)}`);
  prefix.push(hostClause(env.hosts));
  prefix.push(blockedClause(blockedHosts));

  const excluded = opts.includeExcluded ? [] : exclusionClauses(env);
  const parts = ["search", ...prefix, ...excluded, ...(base ? [`(${base})`] : [])];
  return { query: `${parts.join(" ")}${rest ? ` ${rest}` : ""}`, excluded };
}
