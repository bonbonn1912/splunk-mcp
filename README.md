# splunk-mcp

Read-only MCP-Server für selbst gehostetes Splunk Enterprise, gebaut für die Gemini CLI.
19 Tools, mehrere Umgebungen (TEST, TEST2, INT1, INT2, DEMO …), Zugriff über den Management-Port 8089.

Die vollständige Beschreibung aller Tools und Einstellungen steht in [tools.md](tools.md).

## Einrichten

Voraussetzung: Node.js 20 oder neuer.

```bash
npm install
npm run build
```

### 1. Passwort verschlüsseln

```bash
node dist/cli.js encrypt
```

Fragt das Passwort verdeckt ab und gibt `SPLUNK_PASSWORD_ENC` und `SPLUNK_SECRET` aus.

### 2. Zertifikats-Fingerprint je Umgebung holen

```bash
node dist/cli.js fingerprint TEST https://splunk-test.example.lan:8089
```

Zeigt Inhaber und Gültigkeit des Zertifikats und gibt die Zeile `SPLUNK_TLS_FINGERPRINT_TEST` aus.
Für jede Umgebung wiederholen.

### 3. In die Gemini CLI eintragen

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "node",
      "args": ["/Users/dominik/Developer/github/splunk-mcp/dist/cli.js"],
      "env": {
        "SPLUNK_URL_TEST": "https://splunk-test.example.lan:8089",
        "SPLUNK_URL_TEST2": "https://splunk-test2.example.lan:8089",
        "SPLUNK_URL_INT1": "https://splunk-int1.example.lan:8089",
        "SPLUNK_URL_INT2": "https://splunk-int2.example.lan:8089",
        "SPLUNK_URL_DEMO": "https://splunk-demo.example.lan:8089",

        "SPLUNK_TLS_FINGERPRINT_TEST": "AB:CD:…",
        "SPLUNK_TLS_FINGERPRINT_TEST2": "…",
        "SPLUNK_TLS_FINGERPRINT_INT1": "…",
        "SPLUNK_TLS_FINGERPRINT_INT2": "…",
        "SPLUNK_TLS_FINGERPRINT_DEMO": "…",

        "SPLUNK_USERNAME": "dein.benutzer",
        "SPLUNK_PASSWORD_ENC": "v1:…",
        "SPLUNK_SECRET": "…",

        "SPLUNK_APP": "meine_app",
        "SPLUNK_SOURCETYPE_TEST": "mein:sourcetype",
        "SPLUNK_HOST_TEST": "testhost01",
        "SPLUNK_SOURCETYPE_INT1": "mein:sourcetype",
        "SPLUNK_HOST_INT1": "inthost01",

        "SPLUNK_EXCLUDE_ACTUATOR": "true"
      },
      "timeout": 180000
    }
  }
}
```

Danach `chmod 600 ~/.gemini/settings.json`. Die Zugangsdaten gehören nur in diese Benutzer-Datei, nie in eine `settings.json` im Repo.

### 4. Prüfen

In der Gemini CLI `/mcp` aufrufen: Der Server `splunk` sollte 19 Tools zeigen. Dann z. B.:

> Welche Hosts liefern auf INT1 Logs?

Die Konfiguration lässt sich auch ohne Gemini prüfen (liest dieselben Umgebungsvariablen, baut keine Verbindung auf):

```bash
SPLUNK_URL_TEST=… SPLUNK_USERNAME=… SPLUNK_PASSWORD_ENC=… SPLUNK_SECRET=… node dist/cli.js check
```

## Ohne Zertifikatsprüfung oder ohne TLS

- `SPLUNK_TLS_MODE=insecure` (oder `SPLUNK_TLS_MODE_<NAME>`) schaltet die Prüfung ab.
- `http://`-Adressen brauchen `SPLUNK_ALLOW_HTTP=true`. Das Passwort geht dann beim Login unverschlüsselt übers Netz.

## Nach einem Passwortwechsel

`node dist/cli.js encrypt` erneut ausführen, `SPLUNK_PASSWORD_ENC` (und `SPLUNK_SECRET`) ersetzen, Gemini CLI neu starten.
Lehnt Splunk den Login einmal ab, versucht der Server es in keiner Umgebung erneut, bis er neu gestartet wird. Das schützt das AD-Konto vor einer Sperre.

## Entwicklung

```bash
npm run typecheck
SPLUNK_DEBUG=true # protokolliert jeden Splunk-Aufruf auf stderr
```

| Datei | Inhalt |
|---|---|
| `src/cli.ts` | Einstieg: Server starten, `encrypt`, `fingerprint`, `check` |
| `src/config.ts` | Umgebungsvariablen und Umgebungen |
| `src/crypto.ts` | AES-256-GCM für das Passwort |
| `src/client.ts` | HTTP, TLS-Pinning, Login/Session, Lockout-Schutz |
| `src/spl.ts` | SPL-Guard, Standard-Suchbereich, Ausschlussfilter |
| `src/search.ts` | Suchjobs: anlegen, warten, Ergebnisse |
| `src/tools.ts` | Die 19 MCP-Tools |
| `src/format.ts` | Antwortformat und Kürzung |

## Stand

Noch nicht gegen eine echte Splunk-Instanz erprobt.
