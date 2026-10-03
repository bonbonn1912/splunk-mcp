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

Danach gibt es drei Dateien, dazu optional eine vierte:

| Datei | Ort | Inhalt |
|---|---|---|
| `settings.json` | `~/.gemini/` oder `.gemini/` im Projekt | startet den MCP-Server |
| `environments.json` | Projektordner, neben `dist/` | Splunk-Adresse, Hosts der Umgebungen, gesperrte Hosts |
| `.env` | Projektordner, neben `dist/` | das verschlüsselte Passwort |
| `redaction.json` (optional) | Projektordner, neben `dist/` | Regeln für die Pseudonymisierung |

`environments.json`, `.env` und `redaction.json` stehen in `.gitignore`. Vorlagen: `gemini-settings.example.json`,
`environments.example.json`, `.env.example`, `redaction.example.json`. Nach Änderungen an den Dateien den MCP-Server in Gemini neu starten
(`/mcp refresh` oder Gemini neu starten).

### 1. `settings.json`

```json
{
  "mcpServers": {
    "splunk": {
      "command": "node",
      "args": ["dist/cli.js"],
      "cwd": "/path/to/splunk-mcp",
      "timeout": 180000,
      "trust": false
    }
  }
}
```

`cwd` ist der Projektordner. Ein `env`-Block ist nicht nötig.

### 2. `environments.json`

```json
{
  "splunk": {
    "url": "https://splunk.example.lan:8089",
    "tlsFingerprint": "AB:CD:EF:…",
    "user": "dein.benutzer"
  },

  "app": "meine_app",
  "sourcetype": "mein:sourcetype",
  "excludeActuator": true,

  "environments": {
    "TEST": { "description": "Testumgebung 1", "hosts": ["testhost01"] },
    "TEST2": { "description": "Testumgebung 2", "hosts": ["testhost02"] },
    "INT1": { "description": "Integration 1", "hosts": ["inthost01"] },
    "INT2": { "description": "Integration 2", "hosts": ["inthost02"] },
    "DEMO": { "description": "Demo-Umgebung", "hosts": ["demohost01"] }
  },

  "blockedHosts": ["prodhost01"]
}
```

Der Name eines Eintrags unter `environments` ist der Name, unter dem die KI die Umgebung anspricht: Buchstaben und Ziffern,
Groß-/Kleinschreibung egal. Weitere Umgebungen sind einfach weitere Einträge.

**`splunk`: die Verbindung**

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `url` | ja | Management-Port, z. B. `https://splunk.example.lan:8089` |
| `user` | ja | Splunk- bzw. AD-Benutzername |
| `tlsFingerprint` | bei `tlsMode: pinned` | SHA-256-Fingerprint des Zertifikats, siehe Schritt 4 |
| `tlsMode` | nein | `pinned` (Standard), `verify` oder `insecure` |
| `caCert` | nein | Pfad zur CA-Datei, nur für `verify` |
| `allowHttp` | nein | `true` erlaubt eine `http://`-Adresse |
| `webPort`, `webUrl`, `locale` | nein | für den Link in die Splunk-Oberfläche; Standard Port `8443`, `de-DE` |

**`environments.<NAME>`: eine Umgebung**

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `hosts` | ja | Host oder Hosts der Umgebung; Liste, Wildcards wie `int-*` möglich |
| `description` | nein | Beschreibung; daran erkennt die KI, welche Umgebung gemeint ist |
| `app`, `sourcetype`, `index`, `excludeActuator`, `actuatorField`, `excludeTerms`, `allowedIndexes` | nein | überschreibt den Wert der obersten Ebene für diese Umgebung |

**Oberste Ebene: gilt für alle Umgebungen**

| Feld | Pflicht | Bedeutung |
|---|---|---|
| `blockedHosts` | ja* | Hosts, deren Daten nie ausgegeben werden (PROD) |
| `protectedHosts` | ja* | Hosts, die nur pseudonymisiert durchsucht werden dürfen |
| `app` | nein | Splunk-App, Standard `search` |
| `sourcetype`, `index` | nein | wird vor jede Suche gesetzt |
| `excludeActuator` | nein | `true` blendet Spring-`/actuator`-Aufrufe aus |
| `actuatorField`, `excludeTerms` | nein | Feld mit dem Request-Pfad; weitere auszublendende Begriffe |
| `redactionFile` | nein | anderer Pfad für die Pseudonymisierungs-Datei |
| `maxRows`, `maxOutputChars`, `searchTimeoutS`, `defaultEarliest`, `enableKvstore` | nein | Grenzwerte, siehe [tools.md](tools.md) |

\* Eines von beiden muss gesetzt sein, sonst startet der Server nicht.

Ein unbekannter Eintrag (Tippfehler) ist ein Fehler: Der Server startet nicht und nennt den Eintrag.

### 3. `.env`

```bash
node dist/cli.js encrypt --write
```

Fragt das Passwort verdeckt ab und schreibt zwei Zeilen in die `.env` (nur für dich lesbar):

```
SPLUNK_PASSWORD_ENC=v1:...
SPLUNK_SECRET=...
```

Ein Klartext-Passwort wird nicht angenommen. Ohne `--write` gibt der Befehl die beiden Zeilen nur aus.

### 4. Zertifikats-Fingerprint holen

```bash
node dist/cli.js fingerprint
```

Liest die Adresse aus `environments.json`, zeigt Inhaber und Gültigkeit des Zertifikats und gibt die Zeile
`"tlsFingerprint": "…"` aus. Diese unter `splunk` eintragen.

### 5. Prüfen

```bash
node dist/cli.js check
```

Zeigt die gelesene Konfiguration, ohne eine Verbindung aufzubauen. In der Gemini CLI zeigt `/mcp` den Server `splunk`
mit 18 Tools. Dann z. B.:

> Welche Fehler gab es in der letzten Stunde auf INT1?

### Rangfolge

`environments.json` gilt vor allem anderen. Was dort fehlt, kommt aus Umgebungsvariablen (`SPLUNK_*`, z. B. aus einem
`env`-Block der `settings.json`), danach aus der `.env`. Andere Dateinamen: `SPLUNK_ENVIRONMENTS_FILE`, `SPLUNK_ENV_FILE`.

## Schutz der PROD-Daten

1. Jede Suche bekommt zwingend `host=<Umgebung> NOT host=<gesperrt>` vorangestellt. Das Modell kann das nicht abschalten.
2. Suchen, die den Filter umgehen könnten, werden abgelehnt: führende Pipe (`| tstats`, `| inputlookup` …), Subsearches in `[ ]`, Macros und alle Kommandos außerhalb einer festen Liste.
3. Aus jedem Ergebnis werden Zeilen entfernt, die von einem gesperrten Host stammen oder ihn erwähnen.
4. Es lassen sich nur Suchjobs lesen, die der Server selbst gestartet hat.

`allowedIndexes` wird als zusätzlicher fester Index-Filter auf jede Suche angewendet, auch auf die Übersicht der
Sourcetypes. Das Kommando `lookup` und die Funktion `lookup()` sind gesperrt, weil sie Daten außerhalb der gewählten Hosts hinzufügen können.

Der Schutz sitzt in diesem Server, nicht in Splunk. Details und Grenzen: Abschnitt 4.1 in [tools.md](tools.md).

## Personenbezogene Daten pseudonymisieren (optional)

Standardmäßig aus. Zum Einschalten `redaction.example.json` nach `redaction.json` in den Projektordner kopieren und anpassen.
Liegt die Datei dort, ist die Pseudonymisierung an. Ist sie fehlerhaft, startet der Server nicht.

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

Bei `name=wert` ohne Anführungszeichen reicht der Wert bis zum nächsten Komma, zur schließenden Klammer, zum nächsten `name=` oder zum Zeilenende. So werden auch Werte mit Leerzeichen (`lastName=von der Heide`) vollständig ersetzt; steht danach nur noch Fließtext, wird dieser mit ersetzt. Die Hex-Werte in der Tabelle sind Beispiele.

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
- Wildcards dürfen diese Regeln nicht umgehen, etwa durch `rename last* as public*`.
- `addtotals`, `addcoltotals`, `timewrap` und `tags` sind bei aktiver Pseudonymisierung gesperrt, weil sie Werte implizit kopieren oder ihre Feldnamen verändern können.
- Ergebnisse werden vor Feld-Auswahl und Kürzung pseudonymisiert. Metadaten, Hinweise und Fehlermeldungen werden ebenfalls bereinigt.
- Bei aktiver Pseudonymisierung wird `meta.web_url` weggelassen, weil der Link die vollständige Suche enthält.
- Vom Server erzeugte Job-IDs, Umgebungsnamen und Angaben zur Seitennavigation bleiben verwendbar.

### Ausprobieren

```bash
node dist/cli.js redact redaction.json < beispiel.log
```

Gibt die Zeilen pseudonymisiert aus, ohne Gemini und ohne Splunk. Was danach noch lesbar ist, fehlt in der Liste.

### PROD nur pseudonymisiert freigeben

Statt PROD ganz zu sperren, kann der Host als Umgebung angelegt werden. Das geht nur, wenn `redaction.json` vorhanden ist,
sonst startet der Server nicht. In `environments.json`:

```json
"environments": {
  "PROD": { "description": "Produktion, nur pseudonymisiert", "hosts": ["prodhost01"] }
},
"protectedHosts": ["prodhost01"]
```

`blockedHosts` kann daneben weiter Hosts ganz sperren. Details und Grenzen: Abschnitt 4.5 in [tools.md](tools.md).

## Ohne Zertifikatsprüfung oder ohne TLS

- `"tlsMode": "insecure"` unter `splunk` schaltet die Prüfung ab.
- Eine `http://`-Adresse braucht `"allowHttp": true`. Das Passwort geht dann beim Login unverschlüsselt übers Netz.

## Nach einem Passwortwechsel

`node dist/cli.js encrypt --write` erneut ausführen und Gemini CLI neu starten.
Lehnt Splunk den Login einmal ab, versucht der Server es nicht erneut, bis er neu gestartet wird. Das schützt das AD-Konto vor einer Sperre.

## Entwicklung

```bash
npm run typecheck
npm test
SPLUNK_DEBUG=true # protokolliert jeden Splunk-Aufruf auf stderr
```

| Datei | Inhalt |
|---|---|
| `src/cli.ts` | Einstieg: Server starten, `encrypt`, `fingerprint`, `check` |
| `src/files.ts` | Liest `environments.json` und `.env` |
| `src/config.ts` | Prüft die Konfiguration: Umgebungen, gesperrte Hosts |
| `src/crypto.ts` | AES-256-GCM für das Passwort |
| `src/client.ts` | HTTP, TLS-Pinning, Login/Session, Lockout-Schutz |
| `src/spl.ts` | Regeln für Suchen, erzwungener Host-Filter, Ausschlussfilter |
| `src/search.ts` | Suchjobs: anlegen, warten, Ergebnisse, Ergebnisfilter |
| `src/tools.ts` | Die MCP-Tools |
| `src/redact.ts` | Pseudonymisierung |
| `src/format.ts` | Antwortformat und Kürzung |

## Stand

Noch nicht gegen eine echte Splunk-Instanz erprobt.
