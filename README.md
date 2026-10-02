# splunk-mcp

Read-only MCP-Server für selbst gehostetes Splunk Enterprise, gebaut für die Gemini CLI.

- Eine Splunk-Instanz, Zugriff über den Management-Port 8089.
- Umgebungen (TEST, TEST2, INT1, INT2, DEMO …) sind feste Host-Filter: Jede Suche läuft nur auf den Hosts der gewählten Umgebung.
- Gesperrte Hosts (PROD) können weder gesucht noch ausgegeben werden.

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

### 2. Zertifikats-Fingerprint holen

```bash
node dist/cli.js fingerprint https://splunk.example.lan:8089
```

Zeigt Inhaber und Gültigkeit des Zertifikats und gibt die Zeile `SPLUNK_TLS_FINGERPRINT` aus.

### 3. In die Gemini CLI eintragen

`~/.gemini/settings.json`:

```json
{
  "mcpServers": {
    "splunk": {
      "command": "node",
      "args": ["/Users/dominik/Developer/github/splunk-mcp/dist/cli.js"],
      "env": {
        "SPLUNK_URL": "https://splunk.example.lan:8089",
        "SPLUNK_TLS_FINGERPRINT": "AB:CD:…",

        "SPLUNK_USERNAME": "dein.benutzer",
        "SPLUNK_PASSWORD_ENC": "v1:…",
        "SPLUNK_SECRET": "…",

        "SPLUNK_APP": "meine_app",
        "SPLUNK_SOURCETYPE": "mein:sourcetype",
        "SPLUNK_EXCLUDE_ACTUATOR": "true",

        "SPLUNK_HOST_TEST": "testhost01",
        "SPLUNK_HOST_TEST2": "testhost02",
        "SPLUNK_HOST_INT1": "inthost01",
        "SPLUNK_HOST_INT2": "inthost02",
        "SPLUNK_HOST_DEMO": "demohost01",

        "SPLUNK_BLOCKED_HOSTS": "prodhost01"
      },
      "timeout": 180000
    }
  }
}
```

- `SPLUNK_HOST_<NAME>` legt eine Umgebung an. Mehrere Hosts als Kommaliste, Wildcards wie `int-*` sind möglich.
- `SPLUNK_BLOCKED_HOSTS` ist Pflicht: der oder die PROD-Hosts, kommagetrennt, Wildcards möglich. Ohne diese Angabe startet der Server nicht.

Danach `chmod 600 ~/.gemini/settings.json`. Die Zugangsdaten gehören nur in diese Benutzer-Datei, nie in eine `settings.json` im Repo.

### 4. Prüfen

In der Gemini CLI `/mcp` aufrufen: Der Server `splunk` sollte 18 Tools zeigen. Dann z. B.:

> Welche Fehler gab es in der letzten Stunde auf INT1?

Die Konfiguration lässt sich auch ohne Gemini prüfen (liest dieselben Umgebungsvariablen, baut keine Verbindung auf):

```bash
SPLUNK_URL=… SPLUNK_HOST_TEST=… SPLUNK_BLOCKED_HOSTS=… SPLUNK_USERNAME=… SPLUNK_PASSWORD_ENC=… SPLUNK_SECRET=… node dist/cli.js check
```

## Schutz der PROD-Daten

1. Jede Suche bekommt zwingend `host=<Umgebung> NOT host=<gesperrt>` vorangestellt. Das Modell kann das nicht abschalten.
2. Suchen, die den Filter umgehen könnten, werden abgelehnt: führende Pipe (`| tstats`, `| inputlookup` …), Subsearches in `[ ]`, Macros und alle Kommandos außerhalb einer festen Liste.
3. Aus jedem Ergebnis werden Zeilen entfernt, die von einem gesperrten Host stammen oder ihn erwähnen.
4. Es lassen sich nur Suchjobs lesen, die der Server selbst gestartet hat.

Der Schutz sitzt in diesem Server, nicht in Splunk. Details und Grenzen: Abschnitt 4.1 in [tools.md](tools.md).

## Ohne Zertifikatsprüfung oder ohne TLS

- `SPLUNK_TLS_MODE=insecure` schaltet die Prüfung ab.
- Eine `http://`-Adresse braucht `SPLUNK_ALLOW_HTTP=true`. Das Passwort geht dann beim Login unverschlüsselt übers Netz.

## Nach einem Passwortwechsel

`node dist/cli.js encrypt` erneut ausführen, `SPLUNK_PASSWORD_ENC` (und `SPLUNK_SECRET`) ersetzen, Gemini CLI neu starten.
Lehnt Splunk den Login einmal ab, versucht der Server es nicht erneut, bis er neu gestartet wird. Das schützt das AD-Konto vor einer Sperre.

## Entwicklung

```bash
npm run typecheck
SPLUNK_DEBUG=true # protokolliert jeden Splunk-Aufruf auf stderr
```

| Datei | Inhalt |
|---|---|
| `src/cli.ts` | Einstieg: Server starten, `encrypt`, `fingerprint`, `check` |
| `src/config.ts` | Umgebungsvariablen, Umgebungen, gesperrte Hosts |
| `src/crypto.ts` | AES-256-GCM für das Passwort |
| `src/client.ts` | HTTP, TLS-Pinning, Login/Session, Lockout-Schutz |
| `src/spl.ts` | Regeln für Suchen, erzwungener Host-Filter, Ausschlussfilter |
| `src/search.ts` | Suchjobs: anlegen, warten, Ergebnisse, Ergebnisfilter |
| `src/tools.ts` | Die MCP-Tools |
| `src/format.ts` | Antwortformat und Kürzung |

## Stand

Noch nicht gegen eine echte Splunk-Instanz erprobt.
