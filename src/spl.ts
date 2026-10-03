import { globMatch, type EnvironmentConfig } from "./config.js";
import { SplunkMcpError } from "./errors.js";
import type { Redactor } from "./redact.js";

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
  "untable", "xyseries", "transpose", "fieldsummary", "iplocation",
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
export function validateQuery(query: string, env: EnvironmentConfig, redactor?: Redactor): void {
  const blockedHosts = env.blockedHosts;
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
  if (/\blookup\s*\(/i.test(trimmed.replace(/"(?:\\.|[^"\\])*"/g, '""'))) {
    throw notAllowed(
      "The lookup() function is not allowed because it can read data outside the selected environment.",
      "Use fields from the scoped events only; lookup files and collections are not available to searches.",
    );
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
  if (redactor) checkPseudonymisedFields(trimmed, s, redactor);
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

/** Commands that keep field names intact, so a pseudonymised field stays recognisable in the output. */
const KEEPS_FIELD_NAMES = new Set(["search", "where", "stats", "eventstats", "streamstats", "top", "rare", "dedup", "table", "fields", "sort", "fillnull"]);
/** Commands that move values to places where the field name is lost. Not usable while pseudonymisation is on. */
const LOSES_FIELD_NAMES = new Set([
  "transpose", "untable", "xyseries", "fieldsummary", "contingency", "timewrap", "tags", "addtotals", "addcoltotals",
]);
/** Commands where wildcard field operands can copy or transform protected values. */
const WILDCARD_FIELD_COMMANDS = new Set([
  "rename", "stats", "eventstats", "streamstats", "chart", "timechart", "top", "rare",
  "convert", "fieldformat", "bin", "bucket", "replace", "fillnull", "filldown", "strcat",
  "rex", "erex", "spath", "xpath", "extract", "kv", "xmlkv", "multikv",
]);

/** Removes balanced function calls while respecting quoted strings and nesting. */
function removeFunctionCalls(text: string, functionName: string, visit?: (call: string) => void): string {
  let out = "";
  let quote: string | undefined;
  let copiedFrom = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = undefined;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      continue;
    }
    if (text.slice(i, i + functionName.length).toLowerCase() !== functionName.toLowerCase()) continue;
    const before = text[i - 1] ?? " ";
    if (/[A-Za-z0-9_]/.test(before)) continue;
    let open = i + functionName.length;
    while (/\s/.test(text[open] ?? "")) open++;
    if (text[open] !== "(") continue;
    let depth = 1;
    let quoted: string | undefined;
    let end = open + 1;
    for (; end < text.length && depth > 0; end++) {
      const d = text[end]!;
      if (quoted) {
        if (d === "\\") end++;
        else if (d === quoted) quoted = undefined;
      } else if (d === '"' || d === "'") quoted = d;
      else if (d === "(") depth++;
      else if (d === ")") depth--;
    }
    if (depth !== 0) continue;
    visit?.(text.slice(i, end));
    out += text.slice(copiedFrom, i);
    copiedFrom = end;
    i = end - 1;
  }
  return out + text.slice(copiedFrom);
}

function hasWildcardField(command: string, segment: string, unquoted: string): boolean {
  if (command === "rename") return segment.includes("*"); // quoted field names are valid SPL too
  if (["stats", "eventstats", "streamstats", "chart", "timechart", "top", "rare"].includes(command)) {
    // count(*) counts events; other wildcard operands can select protected fields.
    return removeFunctionCalls(segment, "eval").replace(/\bcount\s*\(\s*\*\s*\)/gi, "count() ").includes("*");
  }
  if (["convert", "fieldformat", "bin", "bucket", "replace", "fillnull", "filldown", "strcat", "addtotals", "addcoltotals"].includes(command)) {
    // These commands operate on field selectors (and some support AS aliases).
    // A wildcard operand can hide a protected source even when quoted.
    return segment.includes("*");
  }
  if (["rex", "erex", "spath", "xpath", "extract", "kv", "xmlkv", "multikv"].includes(command)) {
    // These commands name field selectors in options; a quoted wildcard there
    // is still a selector, while wildcards inside a regex/path literal can be data.
    if (/(?:^|\s)(?:field|output|path|fields)\s*=\s*(?:"[^"\r\n]*\*[^"\r\n]*"|'[^'\r\n]*\*[^'\r\n]*'|[A-Za-z_][\w.-]*\*[\w.*-]*)/i.test(segment)) return true;
  }
  return unquoted.includes("*");
}

/**
 * With pseudonymisation on, a blacklisted field must not be copied into a field
 * of another name (eval x=lastName, rename, rex, "as" ...), because the copy
 * would no longer be recognised. Filtering and grouping by it stays possible.
 */
function checkPseudonymisedFields(query: string, s: Structure, redactor: Redactor): void {
  const lost = [...new Set(s.pipeCommands.filter((c) => LOSES_FIELD_NAMES.has(c)))];
  if (lost.length > 0) {
    throw notAllowed(
      `Command not allowed while pseudonymisation is active: ${lost.join(", ")}.`,
      "These commands move values away from their field names. Use stats/table instead.",
    );
  }
  s.pipes.forEach((start, i) => {
    const end = s.pipes[i + 1] ?? query.length;
    const segment = query.slice(start + 1, end);
    const keys = redactor.keysMentioned(segment);
    const command = s.pipeCommands[i] ?? "";
    const unquoted = segment.replace(/"(?:\\.|[^"\\])*"/g, '""');
    // Wildcards can select a protected field without spelling its name (for
    // example `rename last* AS public*`). Fail closed in commands that can
    // copy, extract, or aggregate field values.
    if (redactor.keys.length > 0 && WILDCARD_FIELD_COMMANDS.has(command) && hasWildcardField(command, segment, unquoted)) {
      throw notAllowed(
        `Wildcard field patterns are not allowed in "${command}" while pseudonymisation is active.`,
        "Name fields explicitly so protected values keep their configured field names and can be pseudonymised.",
      );
    }
    if (keys.length === 0) return;
    let protectedEval = false;
    removeFunctionCalls(segment, "eval", (call) => {
      if (redactor.keysMentioned(call).length > 0) protectedEval = true;
    });
    if (protectedEval) {
      throw notAllowed(
        `The pseudonymised field(s) ${keys.join(", ")} cannot be used inside eval() in "${command}".`,
        "Keep protected fields under their original names; do not calculate or copy them into another result field.",
      );
    }
    if (!KEEPS_FIELD_NAMES.has(command) || /\bas\b/i.test(unquoted)) {
      throw notAllowed(
        `The pseudonymised field(s) ${keys.join(", ")} cannot be used in "${command}"${/\bas\b/i.test(unquoted) ? ' with "as"' : ""}.`,
        "Pseudonymised fields may only be filtered (before the first pipe, or with where/search) and grouped or listed under their own name (stats ... by, top, dedup, table, sort). They cannot be copied, renamed or extracted.",
      );
    }
  });
}

export function hostClause(hosts: string[]): string {
  if (hosts.length === 1) return `host=${quote(hosts[0]!)}`;
  return `host IN (${hosts.map(quote).join(", ")})`;
}

/** Mandatory positive index constraint for environments with an index allowlist. */
export function allowedIndexClause(env: EnvironmentConfig): string | undefined {
  if (env.allowedIndexes.length === 0) return undefined;
  return `index IN (${env.allowedIndexes.map(quote).join(", ")})`;
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
export function applyScope(rawQuery: string, env: EnvironmentConfig, opts: ScopeOptions = {}): ScopedQuery {
  const blockedHosts = env.blockedHosts;
  const body = rawQuery.trim().replace(/^search\b\s*/i, "");
  const firstPipe = scan(body).pipes[0] ?? -1;
  const base = (firstPipe === -1 ? body : body.slice(0, firstPipe)).trim();
  const rest = firstPipe === -1 ? "" : body.slice(firstPipe).trim();

  const prefix: string[] = [];
  const allowedIndexes = allowedIndexClause(env);
  if (allowedIndexes) prefix.push(allowedIndexes);
  const index = opts.index ?? env.defaultIndex;
  if (index && !mentions(base, "index")) prefix.push(`index=${quote(index)}`);
  const sourcetype = opts.sourcetype ?? env.defaultSourcetype;
  if (sourcetype && !mentions(base, "sourcetype")) prefix.push(`sourcetype=${quote(sourcetype)}`);
  prefix.push(hostClause(env.hosts));
  if (blockedHosts.length > 0) prefix.push(blockedClause(blockedHosts));

  const excluded = opts.includeExcluded ? [] : exclusionClauses(env);
  const parts = ["search", ...prefix, ...excluded, ...(base ? [`(${base})`] : [])];
  return { query: `${parts.join(" ")}${rest ? ` ${rest}` : ""}`, excluded };
}
