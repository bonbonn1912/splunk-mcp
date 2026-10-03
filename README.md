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
- `SPLUNK_BLOCKED_HOSTS` nennt den oder die PROD-Hosts, kommagetrennt, Wildcards möglich. Ohne diese Angabe (oder `SPLUNK_PROTECTED_HOSTS`, siehe unten) startet der Server nicht.

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

## Personenbezogene Daten pseudonymisieren (optional)

Standardmäßig aus. Zum Einschalten `redaction.example.json` kopieren, anpassen und in der `settings.json` ergänzen:

```json
"SPLUNK_REDACTION_FILE": "/Users/dominik/.gemini/splunk-redaction.json"
```

Ist die Datei angegeben, aber nicht lesbar oder fehlerhaft, startet der Server nicht.

### Aufbau der Datei

```json
{
  "keys": [
    "firstName", "lastName", "birthDate",
    "street", "zipCode", "city",
    "email", "phone",
    "iban", "customerId"
  ],
  "patterns": {
    "builtin": ["email", "iban", "phone"],
    "custom": [
      { "name": "kundennummer", "regex": "KD-\\d{8}" }
    ]
  },
  "salt": "hier-einen-langen-zufaelligen-text-eintragen"
}
```

Es muss mindestens `keys` oder `patterns` etwas enthalten. Die kleinste sinnvolle Datei ist `{ "keys": ["firstName", "lastName"] }`.

**`keys` – nach Namen.** Die Sperrliste: Namen, unter denen personenbezogene Werte in den Logs stehen. Groß- und Kleinschreibung ist egal. Ein Name greift in allen diesen Formen:

| Form | Vorher | Nachher |
|---|---|---|
| JSON | `"lastName":"Mustermann"` | `"lastName":"[lastName#93931a8d]"` |
| XML-Element, auch mit Namespace | `<ns2:lastName>Mustermann</ns2:lastName>` | `<ns2:lastName>[lastName#93931a8d]</ns2:lastName>` |
| XML-Attribut | `customerId="4711"` | `customerId="[customerId#24707ac6]"` |
| `toString()` | `Person(firstName=Max, lastName=Mustermann)` | `Person(firstName=[firstName#c6e9ada4], lastName=[lastName#93931a8d])` |
| logfmt | `lastName=Mustermann msg=done` | `lastName=[lastName#93931a8d] msg=done` |
| Splunk-Feld | Feld `lastName` | ganzer Wert ersetzt |

**`patterns` – nach Aussehen.** Erkennt Werte an ihrer Form, auch wenn kein Feldname davor steht.

- `builtin` schaltet fertige Muster ein, die der Server mitbringt:

  | Name | Erkennt |
  |---|---|
  | `email` | E-Mail-Adressen |
  | `iban` | IBANs, mit oder ohne Leerzeichen |
  | `phone` | Telefonnummern im internationalen Format mit `+` |
  | `creditcard` | Kreditkartennummern (mit Prüfziffer-Kontrolle) |
  | `ipv4` | IP-Adressen |

- `custom` sind eigene Muster. Jeder Eintrag hat einen `name` (steht später im Pseudonym) und einen `regex`. Aus `KD-12345678` wird im Beispiel `[kundennummer#0e1db4a1]`. Backslashes in JSON doppelt schreiben: `\\d` statt `\d`.

**`salt` – optional.** Ein fester Text, der in die Berechnung der Pseudonyme eingeht. Mit `salt` ergibt derselbe Wert auch nach einem Neustart dasselbe Pseudonym. Ohne `salt` wird bei jedem Start neu gewürfelt. Den Text wie ein Passwort behandeln: Wer ihn kennt, kann kurze, häufige Werte wie Vornamen durch Ausprobieren zuordnen.

### Wie das Pseudonym funktioniert

- Derselbe Wert ergibt immer dasselbe Pseudonym, egal in welchem Format er steht. Zählen und Zuordnen bleibt also möglich.
- Ein einmal erkannter Wert (ab 4 Zeichen) wird in der laufenden Sitzung auch dort ersetzt, wo er ohne Namen auftaucht, z. B. in `Kunde Mustermann nicht gefunden`.
- Bei aktiver Pseudonymisierung darf nach gesperrten Feldern gefiltert und gruppiert werden (`stats count by lastName`), aber sie dürfen nicht kopiert, umbenannt oder extrahiert werden (`eval x=lastName`, `rex`).

### Ausprobieren

```bash
node dist/cli.js redact redaction.json < beispiel.log
```

Gibt die Zeilen pseudonymisiert aus, ohne Gemini und ohne Splunk. Was danach noch lesbar ist, fehlt in der Liste.

### PROD nur pseudonymisiert freigeben

Statt PROD ganz zu sperren, kann der Host als Umgebung angelegt werden. Das geht nur zusammen mit der Pseudonymisierung, sonst startet der Server nicht:

```json
"SPLUNK_PROTECTED_HOSTS": "prodhost01",
"SPLUNK_HOST_PROD": "prodhost01",
"SPLUNK_REDACTION_FILE": "/Users/dominik/.gemini/splunk-redaction.json"
```

`SPLUNK_BLOCKED_HOSTS` kann daneben weiter Hosts ganz sperren. Details und Grenzen: Abschnitt 4.5 in [tools.md](tools.md).

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
| `src/redact.ts` | Pseudonymisierung |
| `src/format.ts` | Antwortformat und Kürzung |

## Stand

Noch nicht gegen eine echte Splunk-Instanz erprobt.
