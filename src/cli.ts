#!/usr/bin/env node
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { fetchCertificate } from "./client.js";
import { dotEnvPath, withConfigFiles } from "./files.js";
import { loadConfig, log } from "./config.js";
import { decryptPassword, encryptPassword, generateSecret } from "./crypto.js";
import { SplunkMcpError } from "./errors.js";
import { Redactor } from "./redact.js";
import { createServer, VERSION } from "./server.js";

const HELP = `splunk-mcp ${VERSION} – read-only MCP server for self-hosted Splunk

Usage:
  splunk-mcp                         Start the MCP server on stdio (used by Gemini CLI)
  splunk-mcp encrypt [--write]       Encrypt the Splunk password; --write stores it in .env
  splunk-mcp fingerprint [url]       Show the TLS certificate fingerprint of the Splunk server
  splunk-mcp redact <file.json>      Try a redaction file: reads log lines from stdin, prints them pseudonymised
  splunk-mcp check                   Validate the configuration from the environment variables
  splunk-mcp --help | --version
`;

/** Reads a line from the terminal without echoing it. */
function readHidden(prompt: string): Promise<string> {
  const stdin = process.stdin;
  if (!stdin.isTTY) {
    // Piped input: read the first line.
    return new Promise((resolve) => {
      let data = "";
      stdin.setEncoding("utf8");
      stdin.on("data", (c: string) => (data += c));
      stdin.on("end", () => resolve(data.split(/\r?\n/)[0] ?? ""));
    });
  }
  return new Promise((resolve, reject) => {
    process.stderr.write(prompt);
    let value = "";
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    const finish = (err?: Error) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.removeListener("data", onData);
      process.stderr.write("\n");
      if (err) reject(err);
      else resolve(value);
    };
    const onData = (chunk: string) => {
      for (const ch of chunk) {
        if (ch === "\r" || ch === "\n") return finish();
        if (ch === "\u0003") return finish(new Error("Abgebrochen."));
        if (ch === "\u007f" || ch === "\b") value = value.slice(0, -1);
        else if (ch >= " ") value += ch;
      }
    };
    stdin.on("data", onData);
  });
}

async function cmdEncrypt(args: string[]): Promise<void> {
  const i = args.indexOf("--secret");
  const secret = i >= 0 && args[i + 1] ? args[i + 1]! : generateSecret();
  const password = await readHidden("Splunk-Passwort (wird nicht angezeigt): ");
  if (!password) throw new Error("Kein Passwort eingegeben.");
  if (process.stdin.isTTY) {
    const again = await readHidden("Passwort wiederholen: ");
    if (again !== password) throw new Error("Die Eingaben stimmen nicht überein.");
  }
  const enc = encryptPassword(password, secret);
  if (decryptPassword(enc, secret) !== password) throw new Error("Selbsttest der Verschlüsselung fehlgeschlagen.");
  if (args.includes("--write")) {
    const file = dotEnvPath();
    const kept = existsSync(file)
      ? readFileSync(file, "utf8")
          .split(/\r?\n/)
          .filter((l) => !/^\s*(?:export\s+)?(SPLUNK_PASSWORD_ENC|SPLUNK_SECRET)\s*=/.test(l))
      : ["# Zugangsdaten für splunk-mcp. Nicht einchecken."];
    while (kept.length > 0 && kept[kept.length - 1]!.trim() === "") kept.pop();
    kept.push(`SPLUNK_PASSWORD_ENC=${enc}`, `SPLUNK_SECRET=${secret}`, "");
    writeFileSync(file, kept.join("\n"), { mode: 0o600 });
    chmodSync(file, 0o600);
    process.stderr.write(`\nGespeichert in ${file} (nur für dich lesbar).\n`);
    return;
  }
  process.stderr.write("\nIn die Datei .env im Projektordner eintragen (oder mit --write direkt speichern):\n\n");
  process.stdout.write(`SPLUNK_PASSWORD_ENC=${enc}\nSPLUNK_SECRET=${secret}\n`);
}

async function cmdFingerprint(args: string[]): Promise<void> {
  const raw = args[0] ?? withConfigFiles(process.env).SPLUNK_URL;
  if (!raw) throw new Error('Keine Adresse: "splunk.url" in environments.json eintragen oder so aufrufen: splunk-mcp fingerprint https://host:8089');
  const url = new URL(raw.includes("://") ? raw : `https://${raw}`);
  if (url.protocol !== "https:") throw new Error("Nur https://-Adressen haben ein Zertifikat.");
  const port = Number(url.port || 443);
  const cert = await fetchCertificate(url.hostname, port);
  process.stderr.write(
    `\nZertifikat von ${url.hostname}:${port}\n` +
      `  Inhaber:    ${cert.subject}\n` +
      `  Aussteller: ${cert.issuer}\n` +
      `  Gültig:     ${cert.validFrom}  bis  ${cert.validTo}\n\n` +
      `Bitte prüfen, ob das der erwartete Server ist. Dann in environments.json unter "splunk" eintragen:\n\n`,
  );
  process.stdout.write(`"tlsFingerprint": "${cert.fingerprint256}"\n`);
}

async function cmdRedact(args: string[]): Promise<void> {
  const file = args[0] ?? process.env.SPLUNK_REDACTION_FILE;
  if (!file) throw new Error("Aufruf: splunk-mcp redact redaction.json < beispiel.log");
  const redactor = Redactor.fromFile(file);
  let input = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) input += chunk;
  const lines = input.split(/\r?\n/);
  process.stdout.write(redactor.apply(lines).join("\n"));
}

function cmdCheck(): void {
  const config = loadConfig();
  if (config.passwordEnc && config.secret) decryptPassword(config.passwordEnc, config.secret);
  const c = config.connection;
  const tlsInfo = c.url.startsWith("http://")
    ? "http (unverschlüsselt)"
    : c.tlsMode === "pinned"
      ? c.tlsFingerprint
        ? "pinned"
        : "pinned, ABER tlsFingerprint FEHLT"
      : c.tlsMode;
  process.stdout.write(`Konfiguration ist gültig.\n  Splunk:           ${c.url}  (tls=${tlsInfo})\n`);
  process.stdout.write(`  Gesperrte Hosts:  ${config.blockedHosts.join(", ") || "–"}\n`);
  process.stdout.write(`  Geschützte Hosts: ${config.protectedHosts.join(", ") || "–"}\n`);
  process.stdout.write(
    `  Pseudonymisierung: ${config.redactor ? `an (${config.redactor.keys.length} Schlüssel)` : "aus"}\n  Umgebungen:\n`,
  );
  for (const e of config.environments.values()) {
    process.stdout.write(
      `    ${e.name.padEnd(8)} hosts=${e.hosts.join(",")}  app=${e.app}` +
        `${e.defaultSourcetype ? `  sourcetype=${e.defaultSourcetype}` : ""}` +
        `${e.excludeActuator ? "  actuator=ausgeblendet" : ""}` +
        `${e.isProtected ? "  GESCHÜTZT (nur pseudonymisiert)" : ""}\n`,
    );
  }
}

async function cmdServe(): Promise<void> {
  const config = loadConfig();
  // Fail early on an unusable password instead of on the first tool call.
  if (!config.token && config.passwordEnc && config.secret) decryptPassword(config.passwordEnc, config.secret);
  const { server, pool } = createServer(config);
  const transport = new StdioServerTransport();
  await server.connect(transport);
  log(`v${VERSION} ready. Environments: ${[...config.environments.keys()].join(", ")}. Blocked hosts: ${config.blockedHosts.length}. Pseudonymisation: ${config.redactor ? "on" : "off"}.`);
  const shutdown = () => {
    pool.closeAll();
    process.exit(0);
  };
  process.on("SIGINT", shutdown);
  process.on("SIGTERM", shutdown);
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  switch (cmd) {
    case undefined:
    case "serve":
      return cmdServe();
    case "encrypt":
      return cmdEncrypt(rest);
    case "fingerprint":
      return cmdFingerprint(rest);
    case "redact":
      return cmdRedact(rest);
    case "check":
      return cmdCheck();
    case "--version":
    case "-v":
      process.stdout.write(`${VERSION}\n`);
      return;
    case "--help":
    case "-h":
    case "help":
      process.stdout.write(HELP);
      return;
    default:
      process.stderr.write(`Unbekannter Befehl: ${cmd}\n\n${HELP}`);
      process.exitCode = 2;
  }
}

main().catch((err: unknown) => {
  if (err instanceof SplunkMcpError) {
    process.stderr.write(`[splunk-mcp] ${err.code}: ${err.message}${err.hint ? `\n  ${err.hint}` : ""}\n`);
  } else {
    process.stderr.write(`[splunk-mcp] ${err instanceof Error ? err.message : String(err)}\n`);
  }
  process.exit(1);
});
