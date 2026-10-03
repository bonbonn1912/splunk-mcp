import { createHmac, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { SplunkMcpError } from "./errors.js";

/**
 * Pseudonymisation of personal data in everything the server returns.
 *
 * Configured by an optional JSON file (SPLUNK_REDACTION_FILE):
 *
 *   {
 *     "keys": ["firstName", "lastName", "iban"],
 *     "patterns": { "builtin": ["email", "iban"], "custom": [{ "name": "kundennr", "regex": "KD-\\d{8}" }] },
 *     "salt": "optional fixed text for pseudonyms that stay the same across restarts"
 *   }
 *
 * "keys" is a blacklist of names. A value is replaced wherever such a name
 * labels it: JSON ("key": value), XML (<key>value</key>, key="value"),
 * toString()/logfmt output (key=value) and Splunk fields of that name.
 * The same value always becomes the same token, e.g. [lastName#3fa9c2d1],
 * so records can still be correlated without revealing the value.
 */

export interface RedactionFile {
  keys?: string[];
  patterns?: { builtin?: string[]; custom?: Array<{ name: string; regex: string }> };
  salt?: string;
}

const KEY_NAME = /^[A-Za-z_][A-Za-z0-9_.\-]*$/;
const TOKEN = /^\[[A-Za-z0-9_.\-]+#[0-9a-f]{8}\]$/;

function luhn(digits: string): boolean {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alt = !alt;
  }
  return sum % 10 === 0;
}

const BUILTIN: Record<string, { regex: RegExp; accept?: (match: string) => boolean }> = {
  email: { regex: /[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}/g },
  iban: { regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g },
  phone: { regex: /\+\d{1,3}[ \-\/]?\(?\d{1,5}\)?(?:[ \-\/]?\d{2,}){1,4}/g },
  creditcard: {
    regex: /\b\d(?:[ \-]?\d){12,18}\b/g,
    accept: (m) => luhn(m.replace(/[ \-]/g, "")),
  },
  ipv4: { regex: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g },
};

export const BUILTIN_PATTERNS = Object.keys(BUILTIN);

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Finds the end (exclusive) of a JSON object/array starting at `start`, or -1. */
function balancedEnd(text: string, start: number): number {
  const open = text[start];
  const close = open === "{" ? "}" : "]";
  let depth = 0;
  let inString = false;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (inString) {
      if (c === "\\") i++;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') inString = true;
    else if (c === open) depth++;
    else if (c === close) {
      depth--;
      if (depth === 0) return i + 1;
    }
  }
  return -1;
}

export class Redactor {
  readonly keys: string[];
  private readonly keySet: Set<string>;
  /** lower-case key -> spelling from the file, so one key always gives the same label. */
  private readonly canonical = new Map<string, string>();
  private readonly salt: Buffer;
  private readonly patterns: Array<{ name: string; regex: RegExp; accept?: (m: string) => boolean }> = [];
  private readonly jsonRe?: RegExp;
  private readonly xmlRe?: RegExp;
  private readonly kvRe?: RegExp;
  /** Values already pseudonymised in this session; replaced wherever they show up again. */
  private readonly seen = new Map<string, string>();
  private seenRe?: RegExp;
  private static readonly SEEN_LIMIT = 5000;

  constructor(file: RedactionFile) {
    const keys = file.keys ?? [];
    if (!Array.isArray(keys) || keys.some((k) => typeof k !== "string" || !KEY_NAME.test(k))) {
      throw new SplunkMcpError("CONFIG_ERROR", 'Redaction file: "keys" must be a list of names (letters, digits, _ . -).');
    }
    this.keys = [...new Set(keys.map((k) => k.toLowerCase()))];
    this.keySet = new Set(this.keys);
    for (const k of keys) if (!this.canonical.has(k.toLowerCase())) this.canonical.set(k.toLowerCase(), k);

    for (const name of file.patterns?.builtin ?? []) {
      const b = BUILTIN[name];
      if (!b) {
        throw new SplunkMcpError("CONFIG_ERROR", `Redaction file: unknown builtin pattern "${name}". Available: ${BUILTIN_PATTERNS.join(", ")}.`);
      }
      this.patterns.push({ name, ...b });
    }
    for (const c of file.patterns?.custom ?? []) {
      if (!c || typeof c.name !== "string" || !KEY_NAME.test(c.name) || typeof c.regex !== "string") {
        throw new SplunkMcpError("CONFIG_ERROR", 'Redaction file: each custom pattern needs "name" and "regex".');
      }
      try {
        this.patterns.push({ name: c.name, regex: new RegExp(c.regex, "g") });
      } catch (e) {
        throw new SplunkMcpError("CONFIG_ERROR", `Redaction file: invalid regex for "${c.name}": ${(e as Error).message}`);
      }
    }
    if (this.keys.length === 0 && this.patterns.length === 0) {
      throw new SplunkMcpError("CONFIG_ERROR", 'Redaction file: define at least one entry in "keys" or "patterns".');
    }
    this.salt = file.salt ? Buffer.from(String(file.salt), "utf8") : randomBytes(32);

    if (this.keys.length > 0) {
      const alt = this.keys.map(escapeRe).join("|");
      // "key": <value>   also with escaped quotes (JSON inside a JSON string): \"key\": \"value\"
      this.jsonRe = new RegExp(`(\\\\?")(${alt})(\\\\?"\\s*:\\s*)`, "gi");
      // <ns:key attr="x">content</ns:key>
      this.xmlRe = new RegExp(`(<((?:[\\w.\\-]+:)?(?:${alt}))(?:\\s[^<>]*?)?>)([\\s\\S]*?)(</\\2\\s*>)`, "gi");
      // key=value   key='value'   key="value"   (toString(), logfmt, XML attributes, query strings)
      this.kvRe = new RegExp(
        `(?<![A-Za-z0-9_])(${alt})(\\s*=\\s*)(?:(\\[[\\w.\\-]+#[0-9a-f]{8}\\])|(\\[[^\\]\\r\\n]*\\])|'([^']*)'|"([^"]*)"|([^\\s,;)\\]}&<>"'][^,;)\\]}&<>\\r\\n]*?)(?=\\s+[A-Za-z_][\\w.]*\\s*=|\\s*[,;)\\]}&<>\\r\\n]|\\s*$))`,
        "gi",
      );
    }
  }

  static fromFile(path: string): Redactor {
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch {
      throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_REDACTION_FILE cannot be read: ${path}`, {
        hint: "The server does not start without it, so that nothing is returned unpseudonymised by accident.",
      });
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch (e) {
      throw new SplunkMcpError("CONFIG_ERROR", `SPLUNK_REDACTION_FILE is not valid JSON: ${(e as Error).message}`);
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new SplunkMcpError("CONFIG_ERROR", "SPLUNK_REDACTION_FILE must contain a JSON object.");
    }
    return new Redactor(parsed as RedactionFile);
  }

  /** Blacklisted keys that appear as a word in the text: person.lastName, values(lastName), lastName_p1 ... */
  keysMentioned(text: string): string[] {
    if (this.keySet.size === 0) return [];
    const lower = text.toLowerCase();
    const parts = new Set(lower.split(/[^a-z0-9]+/));
    return this.keys.filter((k) => parts.has(k) || (/[^a-z0-9]/.test(k) && lower.includes(k)));
  }

  isKeyName(name: string): boolean {
    return this.keysMentioned(name).length > 0;
  }

  pseudonym(label: string, value: string): string {
    const v = value.trim();
    if (v === "" || TOKEN.test(v)) return value;
    const known = this.seen.get(v);
    const hash = createHmac("sha256", this.salt).update(v).digest("hex").slice(0, 8);
    const token = `[${this.canonical.get(label.toLowerCase()) ?? label}#${hash}]`;
    if (!known && v.length >= 4 && this.seen.size < Redactor.SEEN_LIMIT) {
      this.seen.set(v, token);
      this.seenRe = undefined;
    }
    return token;
  }

  private redactJson(text: string): string {
    const re = this.jsonRe!;
    re.lastIndex = 0;
    let out = "";
    let pos = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text))) {
      const key = m[2]!;
      const valueStart = m.index + m[0].length;
      const first = text[valueStart];
      let valueEnd = -1;
      if (first === "{" || first === "[") {
        valueEnd = balancedEnd(text, valueStart);
      } else if (first === '"' || (first === "\\" && text[valueStart + 1] === '"')) {
        const escaped = first === "\\";
        // Find the closing quote of the same escaping level.
        let i = valueStart + (escaped ? 2 : 1);
        for (; i < text.length; i++) {
          if (escaped) {
            if (text[i] === "\\" && text[i + 1] === '"') break;
            if (text[i] === "\\" && text[i + 1] === "\\") i += 3; // \\\" inside an escaped string
          } else {
            if (text[i] === "\\") i++;
            else if (text[i] === '"') break;
          }
        }
        if (i < text.length) valueEnd = i + (escaped ? 2 : 1);
      } else {
        const lit = /^[^,}\]\s]+/.exec(text.slice(valueStart));
        if (lit) valueEnd = valueStart + lit[0].length;
      }
      if (valueEnd === -1) continue;
      const rawValue = text.slice(valueStart, valueEnd);
      if (rawValue === "null") continue;
      const inner = rawValue.replace(/^\\?"|\\?"$/g, "");
      const quoteMark = m[1]!; // " or \"
      out += text.slice(pos, valueStart) + quoteMark + this.pseudonym(key, inner) + quoteMark;
      pos = valueEnd;
      re.lastIndex = valueEnd;
    }
    return out + text.slice(pos);
  }

  /** Pseudonymises everything in a piece of text that a rule matches. */
  redactText(text: string): string {
    if (text === "") return text;
    let out = text;
    if (this.keys.length > 0) {
      out = this.redactJson(out);
      out = out.replace(this.xmlRe!, (_all, open: string, tag: string, content: string, close: string) => {
        if (content.trim() === "") return `${open}${content}${close}`;
        const key = tag.includes(":") ? tag.slice(tag.indexOf(":") + 1) : tag;
        return `${open}${this.pseudonym(key, content)}${close}`;
      });
      out = out.replace(this.kvRe!, (all, key: string, eq: string, token?: string, listValue?: string, sq?: string, dq?: string, bare?: string) => {
        if (token !== undefined) return all;
        if (listValue !== undefined) return `${key}${eq}${this.pseudonym(key, listValue)}`;
        if (sq !== undefined) return `${key}${eq}'${this.pseudonym(key, sq)}'`;
        if (dq !== undefined) return `${key}${eq}"${this.pseudonym(key, dq)}"`;
        if (bare !== undefined && bare !== "null") return `${key}${eq}${this.pseudonym(key, bare)}`;
        return all;
      });
    }
    for (const p of this.patterns) {
      p.regex.lastIndex = 0;
      out = out.replace(p.regex, (match) => (p.accept && !p.accept(match) ? match : this.pseudonym(p.name, match)));
    }
    // Values seen before are replaced even where no rule matches the context.
    if (this.seen.size > 0) {
      this.seenRe ??= new RegExp(
        [...this.seen.keys()]
          .sort((a, b) => b.length - a.length)
          .map(escapeRe)
          .join("|"),
        "g",
      );
      out = out.replace(this.seenRe, (match) => this.seen.get(match) ?? match);
    }
    return out;
  }

  private redactWhole(label: string, value: unknown): unknown {
    if (value === null || value === undefined || value === "") return value;
    if (Array.isArray(value)) return value.map((v) => this.redactWhole(label, v));
    if (typeof value === "object") return this.pseudonym(label, JSON.stringify(value));
    return this.pseudonym(label, String(value));
  }

  /**
   * Pseudonymises a complete result. Two passes: a value that is only recognised
   * late (e.g. in row 5) is then also replaced where it appeared unlabelled earlier.
   */
  apply<T>(data: T): T {
    return this.redactValue(this.redactValue(data)) as T;
  }

  /** Walks any result structure: values under blacklisted names are replaced, all other strings are scanned. */
  redactValue(value: unknown): unknown {
    if (typeof value === "string") return this.redactText(value);
    if (Array.isArray(value)) return value.map((v) => this.redactValue(v));
    if (value && typeof value === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (this.isKeyName(k)) {
          const label = this.keysMentioned(k)[0] ?? k;
          out[k] = this.redactWhole(label, v);
        } else {
          out[k] = this.redactValue(v);
        }
      }
      return out;
    }
    return value;
  }
}
