# splunk-mcp – Tool-Spezifikation

MCP-Server in TypeScript für **selbst gehostetes Splunk Enterprise**, primär für die **Gemini CLI**.
Dieses Dokument ist die verbindliche Spezifikation der Tools: Namen, Parameter, Rückgaben, Splunk-Endpunkte und Sicherheitsregeln.

- Prosa: Deutsch. Tool-Namen, Parameter und `description`-Strings: Englisch (die liest das Modell).
- Status: v1.3, implementiert in `src/`. Noch nicht gegen eine echte Splunk-Instanz erprobt.
- Zielversion: Splunk Enterprise 10.2.x (v2-Search-Endpunkte, kein v1-Fallback).

---

## 1. Rahmen

| Punkt | Entscheidung |
|---|---|
| Sprache / Runtime | TypeScript, Node.js ≥ 20, ESM |
| SDK | `@modelcontextprotocol/sdk`, Schemas mit `zod` |
| Transport | **stdio** (Standard für Gemini CLI). Streamable HTTP optional später |
| Splunk-Zugriff | **Eine** Splunk-Instanz, REST-API über den Management-Port `8089`. Splunk Web `8443` nur für Links. Immer `output_mode=json` |
| Umgebungen | TEST, TEST2, INT1 … sind **Host-Filter** auf dieser einen Instanz, siehe 1.6 |
| Gesperrte Hosts | Der PROD-Host ist entweder ganz gesperrt oder nur pseudonymisiert nutzbar, siehe 4.1 und 4.5 |
| Pseudonymisierung | Optional über eine eigene Datei, Standard aus, siehe 4.5 |
| Authentifizierung | Benutzer + verschlüsselt abgelegtes Passwort (siehe 1.5); einmaliger Login, danach Session-Key. Bearer-Token optional |
| TLS | Self-signed Zertifikate per Fingerprint-Pinning (Standard), siehe 1.7. Unverschlüsseltes HTTP nur mit explizitem Flag |
| Modus | **Ausschließlich read-only**. Es gibt keine schreibenden Tools |

### 1.1 Konfiguration

Die Konfiguration liegt in Dateien im Projektordner neben `dist/` (gleiches Schema wie beim `oracle-mcp`):

| Datei | Inhalt |
|---|---|
| `environments.json` | Splunk-Adresse, Hosts der Umgebungen, gesperrte Hosts, Standardwerte |
| `.env` | `SPLUNK_PASSWORD_ENC` und `SPLUNK_SECRET` |
| `redaction.json` (optional) | Pseudonymisierung; ist die Datei vorhanden, ist sie an |

Felder und Beispiele stehen in der [README](README.md). Jedes Feld der `environments.json` entspricht einer der
Variablen unten; die Datei hat Vorrang, danach gelten Umgebungsvariablen, danach die `.env`. Unbekannte Einträge in
der Datei sind ein Fehler.

| `environments.json` | Variable |
|---|---|
| `splunk.url`, `.user`, `.tlsMode`, `.tlsFingerprint`, `.caCert`, `.allowHttp`, `.webPort`, `.webUrl`, `.locale` | `SPLUNK_URL`, `SPLUNK_USERNAME`, `SPLUNK_TLS_MODE`, `SPLUNK_TLS_FINGERPRINT`, `SPLUNK_CA_CERT`, `SPLUNK_ALLOW_HTTP`, `SPLUNK_WEB_PORT`, `SPLUNK_WEB_URL`, `SPLUNK_LOCALE` |
| `environments.<NAME>.hosts`, `.description` | `SPLUNK_HOST_<NAME>`, `SPLUNK_DESCRIPTION_<NAME>` |
| `blockedHosts`, `protectedHosts`, `redactionFile` | `SPLUNK_BLOCKED_HOSTS`, `SPLUNK_PROTECTED_HOSTS`, `SPLUNK_REDACTION_FILE` |
| `app`, `sourcetype`, `index`, `excludeActuator`, `actuatorField`, `excludeTerms`, `allowedIndexes` (oben oder je Umgebung) | `SPLUNK_APP`, `SPLUNK_SOURCETYPE`, … (je Umgebung mit Suffix `_<NAME>`) |
| `maxRows`, `maxOutputChars`, `searchTimeoutS`, `defaultEarliest`, `enableKvstore` | `SPLUNK_MAX_ROWS`, … |

Die Variablen im Einzelnen:


| Variable | Pflicht | Default | Bedeutung |
|---|---|---|---|
| `SPLUNK_URL` | ja | – | Management-Port der Splunk-Instanz, z. B. `https://splunk.example.lan:8089` |
| `SPLUNK_HOST_<NAME>` | ja (mind. eine) | – | Legt die Umgebung `<NAME>` an und nennt ihre Hosts, z. B. `SPLUNK_HOST_INT1=inthost01`. Kommaliste und Wildcard (`int-*`) möglich |
| `SPLUNK_BLOCKED_HOSTS` | ja** | – | Hosts, deren Daten nie ausgegeben werden dürfen. Kommaliste, Wildcard möglich |
| `SPLUNK_PROTECTED_HOSTS` | ja** | – | Hosts, die nur mit aktiver Pseudonymisierung durchsucht werden dürfen (z. B. PROD). Ohne `SPLUNK_REDACTION_FILE` wirken sie wie gesperrt |
| `SPLUNK_REDACTION_FILE` | nein | – | Pfad zur Pseudonymisierungs-Datei (4.5). Nicht gesetzt = aus |
| `SPLUNK_USERNAME` | ja* | – | Splunk- bzw. AD-Benutzername |
| `SPLUNK_PASSWORD_ENC` | ja* | – | Verschlüsseltes Passwort, Format siehe 1.5 |
| `SPLUNK_SECRET` | ja* | – | Zufälliger 32-Byte-Schlüssel (Base64) zum Entschlüsseln |
| `SPLUNK_TOKEN` | nein | – | Alternative: Authentication Token, falls später freigeschaltet |
| `SPLUNK_TLS_MODE` | nein | `pinned` | `pinned` \| `verify` \| `insecure`, siehe 1.7 |
| `SPLUNK_TLS_FINGERPRINT` | bei `pinned` | – | SHA-256-Fingerprint des Server-Zertifikats |
| `SPLUNK_CA_CERT` | nein | – | Pfad zu PEM-Datei der internen CA, nur für `verify` |
| `SPLUNK_ALLOW_HTTP` | nein | `false` | Erlaubt eine `http://`-URL (Passwort geht dann unverschlüsselt übers Netz) |
| `SPLUNK_APP` | nein | `search` | App-Name (`…/app/<app>/search`), zugleich App-Kontext für die API |
| `SPLUNK_SOURCETYPE` | nein | – | Standard-Sourcetype für alle Umgebungen |
| `SPLUNK_INDEX` | nein | – | Standard-Index, falls nötig |
| `SPLUNK_EXCLUDE_ACTUATOR` | nein | `false` | `true` blendet Spring-Boot-Actuator-Aufrufe (`/actuator…`) aus jeder Suche aus. Siehe 1.10 |
| `SPLUNK_ACTUATOR_FIELD` | nein | – | Feld mit dem Request-Pfad (z. B. `uri`); ohne Angabe Filter auf den Rohtext |
| `SPLUNK_EXCLUDE_TERMS` | nein | – | Weitere auszublendende Begriffe/Pfade, kommagetrennt |
| `SPLUNK_ALLOWED_INDEXES` | nein | – | Kommagetrennte Allowlist; leer = alle laut Rolle |
| `SPLUNK_ENABLE_KVSTORE` | nein | `false` | Schaltet `splunk_query_kvstore` frei. Standardmäßig aus, weil KV-Store-Inhalte keinem Host zugeordnet sind |
| `SPLUNK_WEB_PORT` | nein | `8443` | Port von Splunk Web, für `meta.web_url`. Abweichende Adresse per `SPLUNK_WEB_URL` |
| `SPLUNK_LOCALE` | nein | `de-DE` | Sprachpräfix im Splunk-Web-Pfad |
| `SPLUNK_DEFAULT_EARLIEST` | nein | `-24h` | Zeitfenster, wenn das Modell keines angibt |
| `SPLUNK_MAX_ROWS` | nein | `1000` | Harte Obergrenze für Ergebniszeilen pro Aufruf |
| `SPLUNK_MAX_OUTPUT_CHARS` | nein | `40000` | Harte Obergrenze für die Antwortgröße |
| `SPLUNK_SEARCH_TIMEOUT_S` | nein | `120` | Max. Wartezeit für `splunk_search` |
| `SPLUNK_REQUEST_TIMEOUT_MS` | nein | `60000` | Zeitlimit je HTTP-Anfrage an Splunk |
| `SPLUNK_DEBUG` | nein | `false` | Protokolliert jeden Splunk-Aufruf auf stderr |

\*\* Mindestens eine der beiden muss gesetzt sein, sonst startet der Server nicht.

\* Entfällt, wenn `SPLUNK_TOKEN` gesetzt ist. Ein Klartext-`SPLUNK_PASSWORD` wird bewusst **nicht** unterstützt.

Je Umgebung überschreibbar (Suffix `_<NAME>`): `SPLUNK_APP`, `SPLUNK_SOURCETYPE`, `SPLUNK_INDEX`, `SPLUNK_ALLOWED_INDEXES`, `SPLUNK_EXCLUDE_ACTUATOR`, `SPLUNK_ACTUATOR_FIELD`, `SPLUNK_EXCLUDE_TERMS`.

### 1.2 Gemini-CLI-Einbindung

`~/.gemini/settings.json`:

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

- `cwd` ist der Projektordner. Ein `env`-Block ist nicht nötig; alles Weitere steht in `environments.json` und `.env`.
- `timeout` muss über `SPLUNK_SEARCH_TIMEOUT_S` liegen.
- Alle Tools tragen `readOnlyHint: true`.
- Prüfen mit `/mcp` in der Gemini CLI oder mit `node dist/cli.js check`.

### 1.3 Regeln für Gemini-kompatible Schemas

Gemini akzeptiert nur eine Teilmenge von JSON Schema. Deshalb gilt für alle Tools:

1. **Flache Parameter**: nur `string`, `integer`, `number`, `boolean`, `array` von Strings. Keine verschachtelten Objekte.
2. **Keine** `anyOf` / `oneOf` / `allOf`, kein `$ref`, keine Union-Typen, kein `null`-Typ. In zod also kein `.union()`, `.nullable()`, `.discriminatedUnion()`.
3. Optionale Werte werden weggelassen, nicht als `null` gesendet. Defaults stehen in der `description`, angewendet werden sie im Server.
4. `enum` nur auf Strings.
5. Tool-Namen: `snake_case`, Präfix `splunk_`, nur `[a-z0-9_]`, höchstens 40 Zeichen (die CLI kann den Servernamen voranstellen).
6. Jede `description` beginnt mit dem Zweck in einem Satz und sagt, **wann** das Tool zu wählen ist und welches Tool typischerweise danach folgt.
7. Zeitangaben immer als Splunk-Zeitmodifikator-String (`-15m`, `-7d@d`, `2026-10-01T00:00:00`), nie als Objekt.

### 1.4 Antwortformat

Alle Tools liefern genau einen `text`-Content mit kompaktem JSON:

```json
{
  "ok": true,
  "data": [ ... ],
  "meta": { "count": 50, "total": 1234, "truncated": true, "next_offset": 50, "sid": "…" },
  "hint": "Result truncated. Call splunk_get_job_results with offset=50 or narrow the search."
}
```

- `truncated` + `hint` sind Pflicht, sobald gekürzt wurde, damit das Modell nicht von Vollständigkeit ausgeht.
- Interne Felder (`_bkt`, `_cd`, `_si`, `_serial`, `_indextime`, …) werden entfernt; `_time` und `_raw` bleiben. `_raw` wird pro Event auf 2000 Zeichen gekürzt.
- Fehler: `isError: true` und `{ "ok": false, "error": { "code", "message", "splunk_messages": [] }, "hint": "…" }`. Splunk-Meldungen (z. B. SPL-Syntaxfehler) werden wörtlich durchgereicht, damit das Modell sich selbst korrigieren kann.

### 1.5 Passwort-Verschlüsselung

Das Passwort steht nie im Klartext in einer Datei. In der `.env` im Projektordner liegen zwei Werte:

| Wert | Inhalt |
|---|---|
| `SPLUNK_SECRET` | 32 zufällige Bytes (`crypto.randomBytes(32)`), Base64 |
| `SPLUNK_PASSWORD_ENC` | `v1:<iv>:<authTag>:<ciphertext>`, alle Teile Base64 |

- **Verfahren:** AES-256-GCM (`node:crypto`), 12-Byte-IV zufällig pro Verschlüsselung, 16-Byte-Auth-Tag. Das Secret ist direkt der Schlüssel; eine KDF ist bei echtem Zufall nicht nötig.
- **Weitere Befehle:** `node dist/cli.js check` prüft die Konfiguration aus den Umgebungsvariablen, ohne eine Verbindung aufzubauen.
- **Hilfsbefehl:** `node dist/cli.js encrypt --write` fragt das Passwort verdeckt ab (kein Echo, keine Shell-History), erzeugt ein neues Secret und schreibt beide Zeilen in die `.env` (Dateirechte 600). Ohne `--write` werden die Zeilen nur ausgegeben.
- **Start:** Der Server entschlüsselt im Speicher, meldet sich einmal über `POST /services/auth/login` an und nutzt danach nur noch den Session-Key (`Authorization: Splunk <key>`). Das Passwort geht so nur beim Login übers Netz, nicht bei jeder Anfrage. Läuft die Session ab (401), wird einmal neu angemeldet.
- **Fehler:** Falsches Secret oder veränderter Wert ergibt `DECRYPT_FAILED`; ein fehlgeschlagener Login wird **nicht** wiederholt, damit das AD-Konto nicht gesperrt wird.
- **Nach AD-Passwortwechsel:** `encrypt` erneut ausführen und `SPLUNK_PASSWORD_ENC` ersetzen.

**Grenze dieses Schutzes:** Passwort und Schlüssel liegen in derselben Datei. Das verhindert Mitlesen am Bildschirm und zufälliges Auffinden per Textsuche, nicht aber das Entschlüsseln durch jemanden, der die Datei kopiert. Deshalb:

- Die `.env` wird von `encrypt --write` mit Dateirechten 600 angelegt und steht in `.gitignore`.
- Datei von Cloud-Sync und geteilten Backups ausnehmen.

### 1.6 Umgebungen

Es gibt **eine** Splunk-Instanz. Eine Umgebung ist nichts anderes als ein fester Host-Filter darauf.

- **Definition:** Jede Variable `SPLUNK_HOST_<NAME>` legt eine Umgebung an (Name aus Großbuchstaben und Ziffern). Der Wert nennt den oder die Hosts: einzelner Name, Kommaliste oder Wildcard.
- **Auswahl:** Jedes Tool hat den Pflichtparameter `environment` (String-Enum aus den konfigurierten Namen). Es gibt keinen Default und keinen gemerkten Zustand: Nennt der Benutzer keine Umgebung, muss Gemini nachfragen.
- **Wirkung:** Jede Suche bekommt zwingend `host=<Hosts der Umgebung>` vorangestellt. Das lässt sich pro Aufruf **nicht** überschreiben oder abschalten.
- **Gemeinsam für alle Umgebungen:** URL, Zertifikat, Zugangsdaten, Sourcetype. Es gibt nur eine Anmeldung und eine Session.
- **Job-IDs:** Eine `sid` gilt nur in der Umgebung und Sitzung, die sie erzeugt hat. Jede Antwort trägt `meta.environment`.
- **PROD:** Zwei Möglichkeiten. Entweder steht der PROD-Host in `SPLUNK_BLOCKED_HOSTS` und ist gar nicht erreichbar. Oder er steht in `SPLUNK_PROTECTED_HOSTS` und wird als Umgebung angelegt (`SPLUNK_HOST_PROD=…`); das geht nur zusammen mit `SPLUNK_REDACTION_FILE`, sonst startet der Server nicht. In allen anderen Umgebungen bleibt der PROD-Host gesperrt.

### 1.7 TLS bei self-signed oder fehlendem Zertifikat

Splunk liefert den Management-Port 8089 standardmäßig mit TLS und einem selbst signierten Zertifikat aus. Der Server unterstützt drei Modi (`SPLUNK_TLS_MODE`):

| Modus | Verhalten | Wann |
|---|---|---|
| `pinned` (Default) | Keine CA-Prüfung, aber das Zertifikat muss exakt den hinterlegten SHA-256-Fingerprint haben | Self-signed Zertifikate |
| `verify` | Normale Prüfung gegen System-CAs bzw. `SPLUNK_CA_CERT` | Zertifikat von interner CA |
| `insecure` | Keine Prüfung | Nur als Notlösung; Warnung auf stderr |

- **Fingerprint holen:** `node dist/cli.js fingerprint` liest die Adresse aus `environments.json`, verbindet sich einmal, zeigt Aussteller, Gültigkeit und Fingerprint und gibt die fertige Zeile für die `environments.json` aus.
- **Zertifikat geändert:** Fehler `TLS_FINGERPRINT_MISMATCH`; es wird **kein** Login gesendet. Fingerprint neu holen und eintragen.
- **Gar kein TLS (`http://`):** Nur mit `SPLUNK_ALLOW_HTTP=true`. Login und Session-Key gehen dann lesbar übers Netz.
- Der Modus wirkt nur auf die Verbindungen dieses Servers (eigener `https.Agent`); `NODE_TLS_REJECT_UNAUTHORIZED` wird nicht angefasst.

### 1.8 Zugriff: Management-Port 8089, Splunk Web 8443

Der Server spricht die REST-API direkt auf `SPLUNK_URL` (Port 8089) an. Splunk Web (8443) wird nur für Links genutzt: Jede Suchantwort enthält `meta.web_url`, also `https://<host>:8443/{locale}/app/<app>/search?q=…&earliest=…&latest=…`, mit dem sich dieselbe Suche (inklusive Host-Filter) im Browser öffnen lässt.

### 1.9 Aufbau jeder Suche

Das Modell schreibt nur Suchbegriffe und die Pipeline. Der Server baut daraus:

```text
search [index=…] [sourcetype=…] host=<Umgebung> NOT host=<gesperrt> [NOT "/actuator"] ( <Suchbegriffe des Modells> ) | <Pipeline des Modells>
```

| Teil | Herkunft | Abschaltbar? |
|---|---|---|
| `index=` | `SPLUNK_INDEX`, falls gesetzt | entfällt, wenn die Suche selbst `index=` nennt |
| `sourcetype=` | `SPLUNK_SOURCETYPE` | Parameter `sourcetype` ersetzt ihn; entfällt, wenn die Suche selbst `sourcetype=` nennt |
| `host=` | `SPLUNK_HOST_<NAME>` | **nein** |
| `NOT host=` | `SPLUNK_BLOCKED_HOSTS` | **nein** |
| Ausschlussfilter | 1.10 | Parameter `include_excluded=true` |

- Die Suchbegriffe des Modells stehen in Klammern, damit ein `OR` darin den Host-Filter nicht aufweichen kann.
- `meta.effective_query` zeigt immer die tatsächlich ausgeführte SPL.

### 1.10 Ausschlussfilter (Spring Actuator)

Health-Checks und Metrik-Abrufe auf `/actuator/…` erzeugen viel Rauschen. Mit `SPLUNK_EXCLUDE_ACTUATOR=true` werden sie aus jeder Suche herausgefiltert.

| Konfiguration | Angehängter Filter |
|---|---|
| nur `SPLUNK_EXCLUDE_ACTUATOR=true` | `NOT "/actuator"` (Treffer im Rohtext) |
| zusätzlich `SPLUNK_ACTUATOR_FIELD=uri` | `NOT uri="/actuator*"` (genauer, setzt extrahiertes Feld voraus) |
| `SPLUNK_EXCLUDE_TERMS=/favicon.ico,/health` | je Eintrag ein weiteres `NOT "<term>"` |

- **Abschalten pro Aufruf:** Parameter `include_excluded=true`, z. B. wenn gezielt nach Actuator-Aufrufen gefragt wird.
- **Transparenz:** `meta.excluded` listet die aktiven Ausschlüsse.
- **Grenze des Rohtext-Filters:** Er entfernt auch Events, die `/actuator` nur erwähnen. Wo das stört, `SPLUNK_ACTUATOR_FIELD` setzen.

---

## 2. Übersicht

| # | Tool | Zweck | Modus |
|---|---|---|---|
| 0 | `splunk_list_environments` | Konfigurierte Umgebungen anzeigen | read |
| 1 | `splunk_search` | SPL ausführen, auf Ergebnis warten | read |
| 2 | `splunk_start_search` | Lange Suche asynchron starten | read |
| 3 | `splunk_get_job_status` | Fortschritt eines Jobs | read |
| 4 | `splunk_get_job_results` | Ergebnisse eines Jobs seitenweise | read |
| 5 | `splunk_cancel_job` | Job abbrechen | read* |
| 6 | `splunk_validate_spl` | SPL parsen ohne Ausführung | read |
| 7 | `splunk_list_indexes` | Indizes mit Größe und Zeitraum | read |
| 8 | `splunk_list_sourcetypes` | Sourcetypes / Sources der Umgebung | read |
| 9 | `splunk_get_field_summary` | Felder eines Datenausschnitts | read |
| 10 | `splunk_get_server_info` | Version, Rollen, Lizenz, Health | read |
| 11 | `splunk_get_current_user` | Benutzer, Rollen, Capabilities | read |
| 12 | `splunk_list_saved_searches` | Reports und Alerts | read |
| 13 | `splunk_get_saved_search` | Definition eines Reports/Alerts | read |
| 14 | `splunk_run_saved_search` | Saved Search ausführen | read |
| 15 | `splunk_list_fired_alerts` | Ausgelöste Alerts | read |
| 16 | `splunk_list_knowledge_objects` | Macros, Lookups, Datamodels, Dashboards, Apps | read |
| 17 | `splunk_get_knowledge_object` | Definition eines einzelnen Objekts | read |
| 18 | `splunk_query_kvstore` | KV-Store-Collection lesen (nur mit `SPLUNK_ENABLE_KVSTORE=true`) | read |

\* Bricht nur eigene Jobs ab; verändert keine Daten.

Bewusst **18 (bzw. 19) statt 40 Tools**: Je kleiner die Auswahl, desto treffsicherer wählt Gemini. Knowledge Objects sind deshalb in zwei generischen Tools mit `type`-Enum gebündelt.

---

## 3. Tools im Detail

**Gemeinsamer Parameter:** Alle Tools außer `splunk_list_environments` haben als ersten Pflichtparameter

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `environment` | string enum (die konfigurierten Namen) | ja | "Environment to query. Each environment is a fixed set of hosts. Ask the user if it was not stated; never guess." |

Er ist in den Tabellen unten nicht jedes Mal wiederholt.

### 3.0 Umgebungen

#### `splunk_list_environments`

> List the configured Splunk environments. Use this when the user has not said which environment to use, then ask them to choose.

Keine Parameter. Rückgabe je Umgebung: `name`, `description`, `hosts`, `app`, `default_sourcetype`, `default_index`, `excluded`. Die gesperrten Hosts werden nicht genannt. Baut keine Verbindung auf.

### 3.1 Suche

#### `splunk_search`

> Run an SPL event search and wait for the results. Use this for most questions about log data. The host filter of the environment, the default sourcetype and the exclusion filters are added automatically and cannot be removed; meta.effective_query shows what actually ran. Write only search terms followed by pipes. Not allowed: a leading pipe, subsearches in [ ], macros, and commands that read other data. Always set a time range and keep max_rows small.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `query` | string | ja | Ereignissuche ohne Host-Filter, z. B. `level=ERROR \| stats count by logger`. Darf nicht mit `\|` beginnen |
| `earliest` | string | nein | Default `SPLUNK_DEFAULT_EARLIEST` |
| `latest` | string | nein | Default `now` |
| `max_rows` | integer | nein | Default 100, gedeckelt auf `SPLUNK_MAX_ROWS` |
| `app` | string | nein | App-Kontext, Default `SPLUNK_APP` |
| `fields` | string[] | nein | Nur diese Felder zurückgeben |
| `sourcetype` | string | nein | Ersetzt den Standard-Sourcetype für diesen Aufruf |
| `include_excluded` | boolean | nein | `true` = Ausschlussfilter (1.10) für diesen Aufruf abschalten |

- **Endpunkt:** `POST /servicesNS/{user}/{app}/search/v2/jobs` mit `exec_mode=normal`, dann Polling des Jobs, dann `GET /services/search/v2/jobs/{sid}/results`.
- **Rückgabe:** `data` = Ergebniszeilen; `meta` = `environment`, `sid`, `count`, `total`, `scan_count`, `run_duration_s`, `earliest`, `latest`, `truncated`, `effective_query`, `hosts`, `excluded`, `blocked_rows` (falls Zeilen entfernt wurden), `web_url`.
- **Verhalten:** Regeln und Host-Schutz aus 4.1 vor dem Absenden und auf den Ergebnissen. Bei Timeout wird der Job **nicht** abgebrochen, sondern `sid` plus Hinweis auf `splunk_get_job_status` zurückgegeben.

#### `splunk_start_search`

> Start a long-running SPL event search in the background and return its job id (sid) immediately. Same query rules as splunk_search.

Parameter wie `splunk_search` ohne `max_rows` und `fields`. Rückgabe: `{ sid }`.

#### `splunk_get_job_status`

Gilt für alle drei Job-Tools: Sie akzeptieren nur `sid`s, die dieser Server in dieser Sitzung selbst gestartet hat, und nur in derselben Umgebung. Fremde Jobs (Alerts, Suchen aus der Splunk-Oberfläche) ergeben `UNKNOWN_SID`.

> Check whether a search job is finished and how far it has progressed.

| Parameter | Typ | Pflicht |
|---|---|---|
| `sid` | string | ja |

- **Endpunkt:** `GET /services/search/v2/jobs/{sid}`
- **Rückgabe:** `dispatch_state`, `is_done`, `is_failed`, `done_progress` (0–1), `result_count`, `scan_count`, `run_duration_s`, `messages`.

#### `splunk_get_job_results`

> Fetch a page of results from a finished search job. Use `offset` to page through large result sets.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `sid` | string | ja | |
| `offset` | integer | nein | Default 0 |
| `max_rows` | integer | nein | Default 100 |
| `fields` | string[] | nein | |

- **Endpunkt:** `GET /services/search/v2/jobs/{sid}/results?offset=&count=`
- Ist der Job noch nicht fertig: Fehler `JOB_NOT_DONE` mit Hinweis auf `splunk_get_job_status`.

#### `splunk_cancel_job`

> Cancel a running search job that is no longer needed.

Parameter: `sid` (string, Pflicht). **Endpunkt:** `POST /services/search/v2/jobs/{sid}/control` mit `action=cancel`.

#### `splunk_validate_spl`

> Check an SPL query without running it: first against this server's rules, then for Splunk syntax.

| Parameter | Typ | Pflicht |
|---|---|---|
| `query` | string | ja |
| `app` | string | nein |

- **Ablauf:** Erst die Regeln aus 4.1 (Fehler `QUERY_NOT_ALLOWED` / `BLOCKED_HOST`), dann `GET /servicesNS/-/{app}/search/v2/parser` mit `parse_only=true` auf der vollständigen Suche inklusive Host-Filter.
- **Rückgabe:** `valid`, `commands`, `messages`; `meta.effective_query`.

### 3.2 Daten entdecken

#### `splunk_list_indexes`

> List the indexes the current user can search, with event counts and time coverage. Call this first when you do not know where the data lives.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `filter` | string | nein | Teilstring des Indexnamens |
| `include_internal` | boolean | nein | Auch `_internal`, `_audit` …; Default `false` |

- **Endpunkt:** `GET /services/data/indexes?count=0`
- **Rückgabe je Index:** `name`, `datatype` (event/metric), `total_event_count`, `current_size_mb`, `min_time`, `max_time`, `disabled`.

#### `splunk_list_sourcetypes`

> List the sourcetypes or sources (log files) that the hosts of the environment send, with event counts and first/last time.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `index` | string | nein | Default: `SPLUNK_INDEX`, sonst die Standard-Indizes der Rolle |
| `kind` | string enum `sourcetypes` \| `sources` | nein | Default `sourcetypes` |
| `earliest` | string | nein | Default `-7d` |
| `max_rows` | integer | nein | Default 100 |

- **Umsetzung:** Vom Server gebaut, nicht vom Modell: `| tstats count … where [index=…] host=<Umgebung> NOT host=<gesperrt> by sourcetype | sort - totalCount | head {max_rows}`
- **Rückgabe:** `name`, `total_count`, `first_time`, `last_time`.
- Eine Host-Liste gibt es bewusst nicht mehr: Die Hosts stehen in `splunk_list_environments`, andere Hosts sollen nicht sichtbar werden.

#### `splunk_get_field_summary`

> Show which fields exist in the environment's data, how often they occur and example values.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `index` | string | nein | Default: `SPLUNK_INDEX`, sonst die Standard-Indizes der Rolle |
| `sourcetype` | string | nein | Default: `SPLUNK_SOURCETYPE` |
| `earliest` | string | nein | Default `-1h` |
| `sample_size` | integer | nein | Default 5000 Events |
| `max_fields` | integer | nein | Default 50 |

- **Umsetzung:** `<Präfix aus 1.9> | head {sample_size} | fieldsummary maxvals=5 | sort - count | head {max_fields}`
- **Rückgabe:** `field`, `count`, `distinct_count`, `is_numeric`, `top_values` (max. 5).

#### `splunk_get_server_info`

> Return Splunk version, server roles, license state and health. Use this to check connectivity or when behaviour depends on the Splunk version.

Keine Parameter.
**Endpunkte:** `GET /services/server/info`, `GET /services/server/health/splunkd` (Fehler beim zweiten wird toleriert).
**Rückgabe:** `version`, `build`, `server_name`, `server_roles`, `os_name`, `license_state`, `health`, `kvstore_status`.

#### `splunk_get_current_user`

> Return the authenticated Splunk user with roles, capabilities and default indexes. Use this to explain permission errors.

Keine Parameter. **Endpunkt:** `GET /services/authentication/current-context`.

### 3.3 Reports und Alerts

#### `splunk_list_saved_searches`

> List saved searches (reports and alerts) with their schedule and owner.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `filter` | string | nein | Teilstring im Namen |
| `app` | string | nein | Default: alle Apps (`-`) |
| `only_alerts` | boolean | nein | Nur Einträge mit Alert-Bedingung |
| `only_scheduled` | boolean | nein | |
| `max_rows` | integer | nein | Default 50 |
| `offset` | integer | nein | |

- **Endpunkt:** `GET /servicesNS/-/{app}/saved/searches`
- **Rückgabe:** `name`, `app`, `owner`, `is_scheduled`, `cron_schedule`, `is_alert`, `disabled`, `next_scheduled_time`. Die SPL selbst wird hier **nicht** geliefert (Größe) – dafür `splunk_get_saved_search`.

#### `splunk_get_saved_search`

> Return the full definition of one saved search: SPL, time range, schedule, alert condition and actions.

Parameter: `name` (string, Pflicht), `app` (string, optional).
**Endpunkt:** `GET /servicesNS/-/{app}/saved/searches/{name}`.

#### `splunk_run_saved_search`

> Run the SPL of an existing saved search now, limited to the hosts of the environment, and return the results. Alert actions are not triggered. Only works if the saved SPL is a plain event search.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `name` | string | ja | |
| `app` | string | nein | |
| `earliest` | string | nein | Überschreibt das gespeicherte Zeitfenster |
| `latest` | string | nein | |
| `max_rows` | integer | nein | Default 100 |

- **Umsetzung:** Die gespeicherte Suche wird **nicht** unverändert gestartet. Der Server liest ihre SPL, prüft sie nach den Regeln aus 4.1, stellt den Host-Filter aus 1.9 davor und führt sie wie `splunk_search` aus.
- Gespeicherte Suchen mit Subsearches, Macros oder generierenden Kommandos werden mit `QUERY_NOT_ALLOWED` abgelehnt.

#### `splunk_list_fired_alerts`

> List alerts that have triggered recently, with trigger time and severity.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `name` | string | nein | Nur dieser Alert |
| `max_rows` | integer | nein | Default 50 |

- **Endpunkte:** `GET /services/alerts/fired_alerts` bzw. `…/fired_alerts/{name}`
- **Rückgabe ohne `name`:** je Alert `alert_name`, `triggered_count`, `app`.
- **Rückgabe mit `name`:** die einzelnen Auslösungen mit `trigger_time`, `severity`. Die Ergebnisse der Alert-Jobs sind nicht abrufbar (kein Host-Filter).

### 3.4 Knowledge Objects

#### `splunk_list_knowledge_objects`

> List Splunk knowledge objects of one type: macros, lookups, data models, dashboards or installed apps.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `type` | string enum `macros` \| `lookups` \| `datamodels` \| `dashboards` \| `apps` | ja | |
| `filter` | string | nein | Teilstring im Namen |
| `app` | string | nein | |
| `max_rows` | integer | nein | Default 50 |
| `offset` | integer | nein | |

| `type` | Endpunkt |
|---|---|
| `macros` | `GET /servicesNS/-/{app}/configs/conf-macros` |
| `lookups` | `GET /servicesNS/-/{app}/data/transforms/lookups` |
| `datamodels` | `GET /servicesNS/-/{app}/datamodel/model` |
| `dashboards` | `GET /servicesNS/-/{app}/data/ui/views` |
| `apps` | `GET /services/apps/local` |

Rückgabe einheitlich: `name`, `app`, `owner`, `sharing`, `summary` (typabhängige Kurzinfo, z. B. Macro-Argumente oder Lookup-Dateiname).

#### `splunk_get_knowledge_object`

> Return the full definition of one macro, lookup, data model or dashboard.

| Parameter | Typ | Pflicht |
|---|---|---|
| `type` | string enum `macros` \| `lookups` \| `datamodels` \| `dashboards` | ja |
| `name` | string | ja |
| `app` | string | nein |

- Dashboards: XML/JSON-Quelltext (`eai:data`), gekürzt auf `SPLUNK_MAX_OUTPUT_CHARS`.
- Datamodels: Objekt- und Feldliste statt des rohen JSON.
- Lookup-**Inhalte** sind nicht abrufbar (`inputlookup` ist gesperrt, siehe 4.1).

### 3.5 KV Store

#### `splunk_query_kvstore`

Nur registriert mit `SPLUNK_ENABLE_KVSTORE=true`. KV-Store-Inhalte lassen sich keinem Host zuordnen, deshalb ist das Tool standardmäßig aus. Zeilen, die einen gesperrten Host erwähnen, werden auch hier entfernt.

> Read records from a KV store collection. Omit `collection` to list the collections of an app.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `app` | string | nein | Default `SPLUNK_APP` |
| `collection` | string | nein | Leer = Collections auflisten |
| `query` | string | nein | JSON-Query als String, z. B. `{"status":"open"}` |
| `fields` | string[] | nein | |
| `sort` | string | nein | z. B. `_key:1` |
| `max_rows` | integer | nein | Default 100 |
| `offset` | integer | nein | |

- **Endpunkte:** `GET /servicesNS/nobody/{app}/storage/collections/config` bzw. `…/storage/collections/data/{collection}`
- `query` ist bewusst ein String (Regel 1.3.1); der Server prüft, dass es gültiges JSON ist.

---

## 4. Sicherheit und Leitplanken

### 4.1 Schutz der gesperrten Hosts (PROD)

Daten der Hosts aus `SPLUNK_BLOCKED_HOSTS` dürfen nie in einer Antwort stehen. Dafür greifen vier Ebenen nacheinander:

**1. Konfiguration.** Ohne `SPLUNK_BLOCKED_HOSTS` oder `SPLUNK_PROTECTED_HOSTS` startet der Server nicht. Er startet auch nicht, wenn sich ein Umgebungs-Host mit einem gesperrten Host überschneidet (auch per Wildcard), oder wenn eine Umgebung einen geschützten Host enthält und keine Pseudonymisierung konfiguriert ist. Geschützte Hosts gelten in jeder Umgebung, zu der sie nicht gehören, als gesperrt.

**2. Regeln für die Suche.** Vor dem Absenden wird jede Suche geprüft, auch die SPL gespeicherter Suchen:

| Regel | Grund |
|---|---|
| Kein führendes `\|` (keine generierenden Kommandos wie `tstats`, `metadata`, `inputlookup`, `loadjob`, `rest`) | Sie lesen Daten am Host-Filter vorbei |
| Keine eckigen Klammern, also keine Subsearches (`append`, `join`, `union`, `foreach` …) | Eine Subsearch ist eine zweite Suche ohne Host-Filter |
| Keine Backticks, also keine Macros | Ein Macro kann beliebige SPL enthalten |
| Nach der ersten Pipe nur Kommandos einer festen Liste (`stats`, `eval`, `where`, `rex`, `timechart`, `top`, `table`, `sort`, `lookup` …; vollständig in `src/spl.ts`) | Erlaubt ist nur, was vorhandene Events umformt. Alles Unbekannte, auch App-eigene Kommandos, ist gesperrt |
| Anführungszeichen und Klammern müssen ausgeglichen sein | Sonst ließe sich die Klammer um die Suchbegriffe vorzeitig schließen |
| Der Name eines gesperrten Hosts darf nirgends in der Suche vorkommen | Fehler `BLOCKED_HOST` |

Damit entfallen auch alle schreibenden Kommandos (`delete`, `collect`, `outputlookup`, `sendemail` …).

**3. Erzwungener Filter.** Jede Suche läuft als `search host=<Umgebung> NOT host=<gesperrt> ( … )` (siehe 1.9). Beides kann das Modell nicht abschalten.

**4. Filter auf den Ergebnissen.** Bevor Zeilen zurückgegeben werden, entfernt der Server jede Zeile, deren `host` gesperrt ist oder die den Namen eines gesperrten Hosts in irgendeinem Feld enthält. Die Anzahl steht in `meta.blocked_rows`. Der Filter läuft auf den vollständigen Zeilen, bevor `fields` Spalten ausblendet.

Zusätzlich:

- Job-Tools lesen nur Jobs, die der Server selbst gestartet hat (`UNKNOWN_SID` sonst).
- `splunk_list_sourcetypes` ist auf die Hosts der Umgebung begrenzt; eine Host-Liste über alle Hosts gibt es nicht.
- `splunk_query_kvstore` ist standardmäßig aus.
- Die Namen der gesperrten Hosts gibt der Server dem Modell nicht bekannt.
- Bei gesetzter `SPLUNK_ALLOWED_INDEXES` werden Suchen abgelehnt, die andere Indizes nennen.

**Grenzen.** Der Schutz sitzt in diesem Server, nicht in Splunk. Er verhindert nicht, dass dieselben Zugangsdaten an anderer Stelle (Browser, `curl`) PROD-Daten lesen. Ebene 2 und 3 beruhen darauf, dass dieser Server SPL so zerlegt wie Splunk; Ebene 4 fängt Rohzeilen ab, aber keine aggregierten Werte. Eine echte Garantie gibt nur eine Splunk-Rolle mit Suchfilter (`srchFilter = NOT host=<prod>`), die ein Splunk-Admin einrichten müsste.

### 4.2 Rechte

Der Server arbeitet mit dem persönlichen AD-Konto des Benutzers; einen Service-Benutzer gibt es nicht. Er kann in jeder Umgebung genau das, was die Splunk-Rollen dieses Kontos dort erlauben, und alle Suchen laufen unter diesem Namen (sichtbar in `_audit`). Die Such-Quotas der Rolle (`srchJobsQuota`, `srchDiskQuota`) gelten gemeinsam für den Server und die eigene Arbeit in der Splunk-Oberfläche.

### 4.3 Größe und Laufzeit

- Zeilenlimit (`SPLUNK_MAX_ROWS`) und Zeichenlimit (`SPLUNK_MAX_OUTPUT_CHARS`) werden beide durchgesetzt; das engere gewinnt.
- Gekürzt wird zeilenweise von hinten, nie mitten im JSON.
- Jobs aus `splunk_search` bekommen eine kurze TTL (`auto_cancel=300`), damit keine Reste auf dem Search Head liegen bleiben.

### 4.4 Geheimnisse und Logging

- Passwort, Secret, Session-Key und Token erscheinen weder in Tool-Antworten noch in Logs oder Fehlermeldungen.
- Logs gehen ausschließlich nach **stderr** (stdout gehört dem MCP-Protokoll).
- Jeder Tool-Aufruf wird mit Tool-Name, Dauer, `sid` und Zeilenzahl protokolliert, die SPL nur auf Debug-Level.

### 4.5 Pseudonymisierung personenbezogener Daten

Optional. Aktiv, sobald `SPLUNK_REDACTION_FILE` auf eine Datei zeigt; ohne die Variable ist sie aus. Ist die Datei angegeben, aber nicht lesbar oder fehlerhaft, startet der Server nicht.

**Datei** (Vorlage: `redaction.example.json`):

```json
{
  "keys": ["firstName", "lastName", "birthDate", "iban", "email", "street"],
  "patterns": {
    "builtin": ["email", "iban", "phone"],
    "custom": [{ "name": "kundennummer", "regex": "KD-\\d{8}" }]
  },
  "salt": "optional"
}
```

| Eintrag | Bedeutung |
|---|---|
| `keys` | Sperrliste von Namen, Groß-/Kleinschreibung egal |
| `patterns.builtin` | Eingebaute Muster: `email`, `iban`, `phone` (nur internationales Format mit `+`), `creditcard` (mit Prüfziffer), `ipv4` |
| `patterns.custom` | Eigene reguläre Ausdrücke mit Namen |
| `salt` | Fester Text: Pseudonyme bleiben über Neustarts gleich. Ohne Angabe wird bei jedem Start neu gewürfelt |

**Wo ein Name aus `keys` greift:**

| Form | Beispiel | Ergebnis |
|---|---|---|
| JSON | `"lastName":"Mustermann"` | `"lastName":"[lastName#93931a8d]"` |
| JSON in einem String | `\"lastName\":\"Mustermann\"` | `\"lastName\":\"[lastName#93931a8d]\"` |
| JSON-Objekt/-Liste als Wert | `"address":{…}` | `"address":"[address#…]"` |
| XML-Element, auch mit Namespace | `<ns2:lastName>Mustermann</ns2:lastName>` | `<ns2:lastName>[lastName#93931a8d]</ns2:lastName>` |
| XML-Attribut | `customerId="4711"` | `customerId="[customerId#…]"` |
| `toString()` (Lombok, IntelliJ, Commons) | `Person(firstName=Max, lastName=von der Heide)` | `Person(firstName=[firstName#…], lastName=[lastName#…])` |
| logfmt / Query-String | `lastName=Mustermann msg=done` | `lastName=[lastName#93931a8d] msg=done` |
| Splunk-Feld | `lastName`, `person.lastName{}`, `values(lastName)` | ganzer Wert ersetzt |

- **Pseudonym:** `[<Name>#<8 Hex-Zeichen>]`, berechnet als HMAC-SHA256 des Wertes. Derselbe Wert ergibt immer dasselbe Pseudonym, unabhängig vom Format. Zählen und Zuordnen bleibt also möglich.
- **Bekannte Werte:** Ein einmal pseudonymisierter Wert (ab 4 Zeichen) wird in der laufenden Sitzung auch dort ersetzt, wo er ohne Namen auftaucht, z. B. `Kunde Mustermann nicht gefunden`.
- **Geltung:** Für alle Umgebungen und alle Tools; jede Antwort läuft durch denselben Filter.
- **Ausprobieren:** `node dist/cli.js redact redaction.json < beispiel.log` gibt die Zeilen pseudonymisiert aus.

**Zusätzliche Regeln für Suchen bei aktiver Pseudonymisierung:**

| Erlaubt | Abgelehnt (`QUERY_NOT_ALLOWED`) |
|---|---|
| Filtern: `lastName=Mustermann`, `where lastName="…"` | Kopieren: `eval x=lastName`, `rename lastName as x`, `stats values(lastName) as x` |
| Gruppieren und Auflisten unter eigenem Namen: `stats count by lastName`, `top`, `dedup`, `table`, `sort` | Extrahieren: `rex`, `spath` mit dem Namen |
| | Kommandos, bei denen der Feldname verloren geht: `chart`/`timechart … by lastName`, `transpose`, `untable`, `xyseries`, `fieldsummary`, `contingency` |

Grund: Unter einem anderen Feldnamen würde der Filter den Wert nicht mehr erkennen.

**Grenzen.** Es ist eine Sperrliste: Was keinem Namen und keinem Muster entspricht, bleibt lesbar, etwa ein Name in einem Freitextfeld oder ein Feld, das in `keys` fehlt. Aus einem Feld, das die ganze Nachricht enthält, kann eine Suche mit Zeichenketten-Funktionen Teile herausschneiden, die der Filter nicht zuordnen kann. Über gezieltes Filtern (`lastName=M*`) lässt sich auf Werte schließen. Kurze, häufige Werte wie Vornamen sind bei bekanntem `salt` erratbar. Die Liste sollte deshalb mit `redact` an echten Log-Zeilen geprüft werden, bevor PROD freigegeben wird.

---

## 5. Fehlercodes

| Code | Bedeutung | Hinweis an das Modell |
|---|---|---|
| `AUTH_FAILED` | Login abgelehnt (Passwort falsch/abgelaufen, Konto gesperrt) | Benutzer muss Passwort neu verschlüsseln; nicht erneut versuchen |
| `DECRYPT_FAILED` | `SPLUNK_PASSWORD_ENC` passt nicht zu `SPLUNK_SECRET` | `node dist/cli.js encrypt` neu ausführen |
| `FORBIDDEN` | 403, Capability oder Index fehlt | `splunk_get_current_user` aufrufen |
| `NOT_FOUND` | Objekt oder `sid` unbekannt | Liste abrufen und Namen prüfen |
| `SPL_SYNTAX` | Parser-Fehler | Splunk-Meldung lesen, Query korrigieren |
| `QUERY_NOT_ALLOWED` | Suche verletzt eine Regel aus 4.1 | Als einfache Ereignissuche neu schreiben |
| `BLOCKED_HOST` | Suche nennt einen gesperrten Host | Nicht umgehen; Benutzer informieren |
| `UNKNOWN_SID` | Job nicht von diesem Server gestartet oder andere Umgebung | Suche neu ausführen |
| `INDEX_NOT_ALLOWED` | Index nicht in der Allowlist | Erlaubte Indizes werden mitgeliefert |
| `JOB_NOT_DONE` | Ergebnisse noch nicht verfügbar | `splunk_get_job_status` |
| `JOB_FAILED` | Suchjob ist fehlgeschlagen | Splunk-Meldungen lesen, Query korrigieren |
| `INVALID_ARGUMENT` | Parameter ungültig (z. B. KV-Store-Query kein JSON) | Parameter korrigieren |
| `TLS_FINGERPRINT_MISSING` | Modus `pinned` ohne hinterlegten Fingerprint | `node dist/cli.js fingerprint <url>` ausführen |
| `CONFIG_ERROR` | Konfiguration unvollständig oder fehlerhaft | Server startet nicht; Meldung auf stderr |
| `TIMEOUT` | Wartezeit überschritten, Job läuft weiter | `sid` weiterverwenden |
| `TLS_ERROR` | Zertifikat nicht vertrauenswürdig (`verify`) | `SPLUNK_CA_CERT` setzen oder auf `pinned` wechseln |
| `TLS_FINGERPRINT_MISMATCH` | Zertifikat passt nicht zum hinterlegten Fingerprint | `node dist/cli.js fingerprint` neu ausführen, Benutzer informieren |
| `HTTP_NOT_ALLOWED` | `http://`-URL ohne `SPLUNK_ALLOW_HTTP` | Flag setzen oder `https://` verwenden |
| `UNREACHABLE` | Host/Port nicht erreichbar | `SPLUNK_URL` und Port prüfen |
| `UNKNOWN_ENVIRONMENT` | Umgebung nicht konfiguriert | Gültige Namen werden mitgeliefert; Benutzer fragen |
| `LOGIN_BLOCKED` | Nach `AUTH_FAILED` sind Logins gesperrt | Passwort neu verschlüsseln, Server neu starten |

---

## 6. Typischer Ablauf (für `GEMINI.md`)

```text
0. Umgebung klären (vom Benutzer genannt, sonst nachfragen)
1. splunk_list_sourcetypes            → Welche Logs liefern die Hosts der Umgebung?
2. (optional) splunk_list_indexes     → Welche Indizes gibt es?
3. splunk_get_field_summary(index, …) → Welche Felder?
4. splunk_search(query, earliest, …)  → Aggregiert fragen, kleines max_rows
5. Bei truncated=true                 → Query enger fassen oder splunk_get_job_results(offset)
```

Der Server liefert diesen Ablauf beim Verbinden als MCP-`instructions` mit. Eigene Ergänzungen können zusätzlich in eine `GEMINI.md` geschrieben werden.

### 6.1 Was Gemini selbst herausfindet

| Frage | Quelle |
|---|---|
| Welche Umgebungen und Hosts gibt es? | `splunk_list_environments` |
| Welche Sourcetypes / Log-Dateien liefern die Hosts? | `splunk_list_sourcetypes` |
| Welche Felder gibt es? | `splunk_get_field_summary` |

Das Wissen bleibt nicht zwischen Sitzungen erhalten. Feste Hinweise (wichtige Felder, typische Suchen) können in eine `GEMINI.md` geschrieben werden.

---

## 7. Offene Punkte

- [ ] Erster Lauf gegen die echte Instanz (10.2.7): Login, eine einfache Suche, `splunk_list_sourcetypes`.
- [ ] Hostnamen der Umgebungen und des PROD-Hosts eintragen; prüfen, ob PROD mehrere Hosts hat.
- [ ] `redaction.json` mit den echten Feldnamen füllen und mit `redact` an Beispielzeilen prüfen.
- [ ] Mit einem Splunk-Admin klären, ob eine Rolle mit `srchFilter` möglich ist (siehe Grenzen in 4.1).
- [ ] Enterprise Security im Einsatz? Dann eigene Tools für Notables sinnvoll.
