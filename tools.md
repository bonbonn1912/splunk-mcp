# splunk-mcp – Tool-Spezifikation

MCP-Server in TypeScript für **selbst gehostetes Splunk Enterprise**, primär für die **Gemini CLI**.
Dieses Dokument ist die verbindliche Spezifikation der Tools: Namen, Parameter, Rückgaben, Splunk-Endpunkte und Sicherheitsregeln.

- Prosa: Deutsch. Tool-Namen, Parameter und `description`-Strings: Englisch (die liest das Modell).
- Status: v1.0, implementiert in `src/`. Noch nicht gegen eine echte Splunk-Instanz erprobt.
- Zielversion: Splunk Enterprise 10.2.x (v2-Search-Endpunkte, kein v1-Fallback).

---

## 1. Rahmen

| Punkt | Entscheidung |
|---|---|
| Sprache / Runtime | TypeScript, Node.js ≥ 20, ESM |
| SDK | `@modelcontextprotocol/sdk`, Schemas mit `zod` |
| Transport | **stdio** (Standard für Gemini CLI). Streamable HTTP optional später |
| Splunk-Zugriff | **REST-API über den Management-Port `8089`** (mit AD-Konto per Basic Auth geprüft). Splunk Web `8443` nur für Links und als Ausweichweg, siehe 1.8. Immer `output_mode=json` |
| Authentifizierung | Benutzer + verschlüsselt abgelegtes Passwort (siehe 1.5); einmaliger Login, danach Session-Key. Bearer-Token optional |
| TLS | Self-signed Zertifikate per Fingerprint-Pinning (Standard), siehe 1.7. Unverschlüsseltes HTTP nur mit explizitem Flag |
| Modus | **Ausschließlich read-only**. Es gibt keine schreibenden Tools |

### 1.1 Konfiguration (Umgebungsvariablen)

| Variable | Pflicht | Default | Bedeutung |
|---|---|---|---|
| `SPLUNK_URL_<NAME>` | ja (mind. eine) | – | Eine Variable je Umgebung, z. B. `SPLUNK_URL_INT1=https://splunk-int1.example.lan:8089`. Siehe 1.6 |
| `SPLUNK_WEB_PORT` | nein | `8443` | Port von Splunk Web, für `meta.web_url`. Abweichender Host per `SPLUNK_WEB_URL_<NAME>` |
| `SPLUNK_LOCALE` | nein | `de-DE` | Sprachpräfix im Splunk-Web-Pfad |
| `SPLUNK_REQUEST_TIMEOUT_MS` | nein | `60000` | Zeitlimit je HTTP-Anfrage an Splunk |
| `SPLUNK_DEBUG` | nein | `false` | Protokolliert jeden Splunk-Aufruf auf stderr |
| `SPLUNK_SOURCETYPE_<NAME>` | nein | – | Standard-Sourcetype der Umgebung. Siehe 1.9 |
| `SPLUNK_HOST_<NAME>` | nein | – | Standard-Host der Umgebung; Wildcard (`shop-*`) oder Kommaliste möglich |
| `SPLUNK_INDEX_<NAME>` | nein | – | Standard-Index der Umgebung, falls nötig |
| `SPLUNK_EXCLUDE_ACTUATOR` | nein | `false` | `true` blendet Spring-Boot-Actuator-Aufrufe (`/actuator…`) aus jeder Suche aus. Siehe 1.10 |
| `SPLUNK_ACTUATOR_FIELD` | nein | – | Feld mit dem Request-Pfad (z. B. `uri`); ohne Angabe Filter auf den Rohtext |
| `SPLUNK_EXCLUDE_TERMS` | nein | – | Weitere auszublendende Begriffe/Pfade, kommagetrennt |
| `SPLUNK_USERNAME` | ja* | – | Splunk- bzw. AD-Benutzername |
| `SPLUNK_PASSWORD_ENC` | ja* | – | Verschlüsseltes Passwort, Format siehe 1.5 |
| `SPLUNK_SECRET` | ja* | – | Zufälliger 32-Byte-Schlüssel (Base64) zum Entschlüsseln |
| `SPLUNK_TOKEN` | nein | – | Alternative: Authentication Token, falls später freigeschaltet |
| `SPLUNK_CA_CERT` | nein | – | Pfad zu PEM-Datei der internen CA, nur für `verify` |
| `SPLUNK_TLS_MODE` | nein | `pinned` | `pinned` \| `verify` \| `insecure`, siehe 1.7 |
| `SPLUNK_TLS_FINGERPRINT_<NAME>` | bei `pinned` | – | SHA-256-Fingerprint des Server-Zertifikats der Umgebung |
| `SPLUNK_ALLOW_HTTP` | nein | `false` | Erlaubt `http://`-URLs (Passwort geht dann unverschlüsselt übers Netz) |
| `SPLUNK_APP` | nein | `search` | App-Name (`…/app/<app>/search`), zugleich App-Kontext für die API. Je Umgebung per `SPLUNK_APP_<NAME>` |
| `SPLUNK_DEFAULT_EARLIEST` | nein | `-24h` | Zeitfenster, wenn das Modell keines angibt |
| `SPLUNK_MAX_ROWS` | nein | `1000` | Harte Obergrenze für Ergebniszeilen pro Aufruf |
| `SPLUNK_MAX_OUTPUT_CHARS` | nein | `40000` | Harte Obergrenze für die Antwortgröße |
| `SPLUNK_SEARCH_TIMEOUT_S` | nein | `120` | Max. Wartezeit für `splunk_search` |
| `SPLUNK_ALLOWED_INDEXES` | nein | – | Kommagetrennte Allowlist; leer = alle laut Rolle |
| `SPLUNK_ALLOW_RISKY_SPL` | nein | `false` | Erlaubt riskante SPL-Kommandos (siehe 4.1) |

\* Entfällt, wenn `SPLUNK_TOKEN` gesetzt ist. Ein Klartext-`SPLUNK_PASSWORD` wird bewusst **nicht** unterstützt.

### 1.2 Gemini-CLI-Einbindung

`~/.gemini/settings.json` (oder `.gemini/settings.json` im Projekt):

```json
{
  "mcpServers": {
    "splunk": {
      "command": "node",
      "args": ["/pfad/zu/splunk-mcp/dist/cli.js"],
      "env": {
        "SPLUNK_URL_TEST": "https://splunk-test.example.lan:8089",
        "SPLUNK_URL_TEST2": "https://splunk-test2.example.lan:8089",
        "SPLUNK_URL_INT1": "https://splunk-int1.example.lan:8089",
        "SPLUNK_URL_INT2": "https://splunk-int2.example.lan:8089",
        "SPLUNK_URL_DEMO": "https://splunk-demo.example.lan:8089",
        "SPLUNK_USERNAME": "dein.benutzer",
        "SPLUNK_PASSWORD_ENC": "v1:…:…:…",
        "SPLUNK_SECRET": "…44 Zeichen Base64…",
        "SPLUNK_APP": "meine_app",
        "SPLUNK_EXCLUDE_ACTUATOR": "true",
        "SPLUNK_SOURCETYPE_TEST": "mein:sourcetype",
        "SPLUNK_HOST_TEST": "testhost01",
        "SPLUNK_SOURCETYPE_INT1": "mein:sourcetype",
        "SPLUNK_HOST_INT1": "inthost01",
        "SPLUNK_TLS_FINGERPRINT_TEST": "AB:CD:…",
        "SPLUNK_TLS_FINGERPRINT_INT1": "12:34:…"
      },
      "timeout": 180000,
      "trust": false
    }
  }
}
```

- `timeout` muss über `SPLUNK_SEARCH_TIMEOUT_S` liegen.
- Alle Tools tragen `readOnlyHint: true`.
- Mit `includeTools` / `excludeTools` lässt sich die Tool-Menge pro Projekt einschränken.
- Prüfen mit `/mcp` in der Gemini CLI.

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

Das Passwort steht nie im Klartext in der `settings.json`. Abgelegt werden zwei Werte:

| Wert | Inhalt |
|---|---|
| `SPLUNK_SECRET` | 32 zufällige Bytes (`crypto.randomBytes(32)`), Base64 |
| `SPLUNK_PASSWORD_ENC` | `v1:<iv>:<authTag>:<ciphertext>`, alle Teile Base64 |

- **Verfahren:** AES-256-GCM (`node:crypto`), 12-Byte-IV zufällig pro Verschlüsselung, 16-Byte-Auth-Tag. Das Secret ist direkt der Schlüssel; eine KDF ist bei echtem Zufall nicht nötig.
- **Weitere Befehle:** `node dist/cli.js check` prüft die Konfiguration aus den Umgebungsvariablen, ohne eine Verbindung aufzubauen.
- **Hilfsbefehl:** `node dist/cli.js encrypt` fragt das Passwort verdeckt ab (kein Echo, keine Shell-History), erzeugt ein neues Secret und gibt beide Zeilen fertig für die `settings.json` aus. Mit `--secret <wert>` wird ein vorhandenes Secret wiederverwendet.
- **Start:** Der Server entschlüsselt im Speicher, meldet sich einmal über `POST /services/auth/login` an und nutzt danach nur noch den Session-Key (`Authorization: Splunk <key>`). Das Passwort geht so nur beim Login übers Netz, nicht bei jeder Anfrage. Läuft die Session ab (401), wird einmal neu angemeldet.
- **Fehler:** Falsches Secret oder veränderter Wert ergibt `DECRYPT_FAILED`; ein fehlgeschlagener Login wird **nicht** wiederholt, damit das AD-Konto nicht gesperrt wird.
- **Nach AD-Passwortwechsel:** `encrypt` erneut ausführen und `SPLUNK_PASSWORD_ENC` ersetzen.

**Grenze dieses Schutzes:** Passwort und Schlüssel liegen in derselben Datei. Das verhindert Mitlesen am Bildschirm und zufälliges Auffinden per Textsuche, nicht aber das Entschlüsseln durch jemanden, der die Datei kopiert. Deshalb:

- `chmod 600 ~/.gemini/settings.json`
- Zugangsdaten nur in die Benutzer-Datei `~/.gemini/settings.json`, nie in eine `.gemini/settings.json` im Repo.
- Datei von Cloud-Sync und geteilten Backups ausnehmen.

### 1.6 Umgebungen

Ein Server-Prozess bedient mehrere Splunk-Umgebungen. Vorgesehen sind zunächst **TEST, TEST2, INT1, INT2, DEMO**. PROD ist bewusst nicht konfiguriert.

- **Definition:** Jede Variable `SPLUNK_URL_<NAME>` legt eine Umgebung `<NAME>` an (Großbuchstaben, Ziffern). Eine weitere Umgebung ist nur eine weitere Zeile in der `settings.json`, kein Code.
- **Zugangsdaten:** `SPLUNK_USERNAME`, `SPLUNK_PASSWORD_ENC` und `SPLUNK_SECRET` gelten für alle Umgebungen.
- **Auswahl:** Jedes Tool hat den Pflichtparameter `environment` (String-Enum, zur Laufzeit aus den konfigurierten Namen gebaut). Es gibt **keinen Default und keinen gemerkten Zustand**: Nennt der Benutzer keine Umgebung, muss Gemini nachfragen. So landet nie eine Suche versehentlich auf der falschen Umgebung.
- **Eingabe:** Der Name muss exakt einem konfigurierten Wert entsprechen (Großbuchstaben); das Schema gibt die gültigen Werte als Enum vor.
- **Sessions:** Login erfolgt je Umgebung erst beim ersten Aufruf; der Session-Key wird pro Umgebung im Speicher gehalten.
- **Lockout-Schutz:** Da überall dasselbe AD-Passwort gilt, sperrt ein `AUTH_FAILED` in einer Umgebung alle weiteren Login-Versuche in **allen** Umgebungen bis zum Neustart des Servers.
- **Job-IDs:** Eine `sid` gilt nur in der Umgebung, in der sie erzeugt wurde. Jede Antwort trägt `meta.environment`.
- **Abweichungen je Umgebung (optional):** `SPLUNK_APP_<NAME>`, `SPLUNK_ALLOWED_INDEXES_<NAME>`, `SPLUNK_EXCLUDE_ACTUATOR_<NAME>`, `SPLUNK_TLS_MODE_<NAME>`, `SPLUNK_CA_CERT_<NAME>` überschreiben den globalen Wert.
- **PROD später:** Kommt als `SPLUNK_URL_PROD` hinzu; empfohlen dann mit engeren Limits über die `_PROD`-Varianten.

### 1.7 TLS bei self-signed oder fehlendem Zertifikat

Splunk liefert den Management-Port 8089 standardmäßig mit TLS und einem selbst signierten Zertifikat aus. Der Server unterstützt drei Modi, global oder je Umgebung (`SPLUNK_TLS_MODE_<NAME>`):

| Modus | Verhalten | Wann |
|---|---|---|
| `pinned` (Default) | Keine CA-Prüfung, aber das Zertifikat muss exakt den hinterlegten SHA-256-Fingerprint haben | Self-signed Zertifikate |
| `verify` | Normale Prüfung gegen System-CAs bzw. `SPLUNK_CA_CERT` | Zertifikat von interner CA |
| `insecure` | Keine Prüfung | Nur als Notlösung; Warnung auf stderr bei jedem Start |

- **Fingerprint holen:** `node dist/cli.js fingerprint <NAME>` verbindet sich einmal, zeigt Aussteller, Gültigkeit und Fingerprint und gibt die fertige Zeile für die `settings.json` aus.
- **Zertifikat geändert:** Fehler `TLS_FINGERPRINT_MISMATCH`; es wird **kein** Login gesendet. Fingerprint neu holen und eintragen.
- **Gar kein TLS (`http://`):** Nur mit `SPLUNK_ALLOW_HTTP=true`. Login und Session-Key gehen dann lesbar übers Netz. Da es das AD-Passwort ist, sollte das nur in einem vertrauenswürdigen Netz oder über VPN genutzt werden; besser TLS auf 8089 wieder einschalten (`enableSplunkdSSL = true` in `server.conf`).
- Der Modus wirkt nur auf die Verbindungen dieses Servers (eigener `https.Agent`); `NODE_TLS_REJECT_UNAUTHORIZED` wird nicht angefasst.

### 1.8 Zugriff: Management-Port 8089, Splunk Web 8443

**Standard:** Der Server spricht die REST-API direkt auf `https://<host>:8089` an. Das AD-Konto wird dort akzeptiert (geprüft mit `/services/authentication/current-context`). Alle Endpunkte aus Abschnitt 3 gelten unverändert.

**Splunk Web (8443)** wird im Standard nur für Links genutzt: Jede Suchantwort enthält `meta.web_url`, also `https://<host>:8443/{locale}/app/<app>/search?q=…&earliest=…&latest=…`, mit dem sich dieselbe Suche im Browser öffnen lässt. Host kommt aus `SPLUNK_URL_<NAME>`, Port aus `SPLUNK_WEB_PORT`.

**Ausweichweg über Splunk Web (nicht implementiert):** Falls 8089 in einer Umgebung nicht erreichbar ist, kann die API über Splunk Web laufen: Login über `/{locale}/account/login` (Cookie `cval`, danach Session- und CSRF-Cookie), Aufrufe unter `/{locale}/splunkd/__raw/…` mit `X-Requested-With: XMLHttpRequest` und bei `POST` `X-Splunk-Form-Key`. Ungetestet, funktioniert nicht mit SSO, und einzelne Endpunkte können gesperrt sein (`NOT_EXPOSED`). Wird nur gebaut, wenn eine Umgebung es erfordert.

### 1.9 Standard-Suchbereich je Umgebung

Suchen haben hier typischerweise die Form `search sourcetype=<…> host=<…> …`. Sourcetype und Host sind je Umgebung konfigurierbar (`SPLUNK_SOURCETYPE_<NAME>`, `SPLUNK_HOST_<NAME>`, optional `SPLUNK_INDEX_<NAME>`).

- **Anwendung:** `splunk_search`, `splunk_start_search` und `splunk_get_field_summary` stellen den Standardbereich der gewählten Umgebung vor den Suchausdruck, z. B. `search sourcetype="mein:sourcetype" host="inthost01" <query>`.
- **Überschreiben:** Die Parameter `sourcetype` und `host` am Tool ersetzen den jeweiligen Standard für diesen einen Aufruf.
- **Abschalten:** `ignore_default_scope=true` sucht ohne Standardbereich.
- **Keine doppelte Angabe:** Enthält die Query selbst schon `sourcetype=` bzw. `host=`, wird der jeweilige Standard nicht zusätzlich gesetzt.
- **Generierende Suchen** (Query beginnt mit `|`, z. B. `| tstats`, `| inputlookup`) bleiben unverändert; `meta.scope_applied` ist dann `false`.
- **Transparenz:** `meta.effective_query` zeigt immer die tatsächlich ausgeführte SPL. `splunk_list_environments` liefert je Umgebung `app`, `default_sourcetype`, `default_host`, `default_index`, damit Gemini den Bereich kennt.
- **Host-Wert:** Ein einzelner Name, eine Wildcard (`shop-*`) oder eine Kommaliste, die zu `host IN (…)` wird. Werte werden korrekt in Anführungszeichen gesetzt und escaped.

### 1.10 Ausschlussfilter (Spring Actuator)

Health-Checks und Metrik-Abrufe auf `/actuator/…` erzeugen viel Rauschen. Mit `SPLUNK_EXCLUDE_ACTUATOR=true` werden sie aus jeder Suche herausgefiltert, global oder je Umgebung (`SPLUNK_EXCLUDE_ACTUATOR_<NAME>`).

| Konfiguration | Angehängter Filter |
|---|---|
| nur `SPLUNK_EXCLUDE_ACTUATOR=true` | `NOT "/actuator"` (Treffer im Rohtext) |
| zusätzlich `SPLUNK_ACTUATOR_FIELD=uri` | `NOT uri="/actuator*"` (genauer, setzt extrahiertes Feld voraus) |
| `SPLUNK_EXCLUDE_TERMS=/favicon.ico,/health` | je Eintrag ein weiteres `NOT "<term>"` |

- **Anwendung:** Wie der Standardbereich aus 1.9 – der Filter steht im Basis-Suchausdruck vor der ersten Pipe, damit Splunk die Events gar nicht erst lädt. Gilt für `splunk_search`, `splunk_start_search` und `splunk_get_field_summary`; generierende Suchen (`| …`) und `splunk_run_saved_search` bleiben unverändert.
- **Abschalten pro Aufruf:** Parameter `include_excluded=true`, z. B. wenn gezielt nach Actuator-Aufrufen gefragt wird. `ignore_default_scope` lässt den Ausschlussfilter unberührt.
- **Transparenz:** `meta.effective_query` zeigt den Filter, `meta.excluded` listet die aktiven Ausschlüsse. So kann Gemini bei „0 Treffer" erkennen, dass der Filter die Ursache sein könnte.
- **Grenze des Rohtext-Filters:** Er entfernt auch Events, die `/actuator` nur erwähnen (z. B. in einer Fehlermeldung). Wo das stört, `SPLUNK_ACTUATOR_FIELD` setzen.

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
| 8 | `splunk_list_sourcetypes` | Sourcetypes / Hosts / Sources eines Index | read |
| 9 | `splunk_get_field_summary` | Felder eines Datenausschnitts | read |
| 10 | `splunk_get_server_info` | Version, Rollen, Lizenz, Health | read |
| 11 | `splunk_get_current_user` | Benutzer, Rollen, Capabilities | read |
| 12 | `splunk_list_saved_searches` | Reports und Alerts | read |
| 13 | `splunk_get_saved_search` | Definition eines Reports/Alerts | read |
| 14 | `splunk_run_saved_search` | Saved Search ausführen | read |
| 15 | `splunk_list_fired_alerts` | Ausgelöste Alerts | read |
| 16 | `splunk_list_knowledge_objects` | Macros, Lookups, Datamodels, Dashboards, Apps | read |
| 17 | `splunk_get_knowledge_object` | Definition eines einzelnen Objekts | read |
| 18 | `splunk_query_kvstore` | KV-Store-Collection lesen | read |

\* Bricht nur eigene Jobs ab; verändert keine Daten.

Bewusst **19 statt 40 Tools**: Je kleiner die Auswahl, desto treffsicherer wählt Gemini. Knowledge Objects sind deshalb in zwei generischen Tools mit `type`-Enum gebündelt.

---

## 3. Tools im Detail

**Gemeinsamer Parameter:** Alle Tools außer `splunk_list_environments` haben als ersten Pflichtparameter

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `environment` | string enum (`TEST` \| `TEST2` \| `INT1` \| `INT2` \| `DEMO`) | ja | "Splunk environment to query. Ask the user if it was not stated; never guess." |

Er ist in den Tabellen unten nicht jedes Mal wiederholt.

### 3.0 Umgebungen

#### `splunk_list_environments`

> List the configured Splunk environments. Use this when the user has not said which environment to use, then ask them to choose.

Keine Parameter. Rückgabe je Umgebung: `name`, `url`, `app`, `default_sourcetype`, `default_host`, `default_index`, `excluded`, `session` (`none` \| `active` \| `failed`). Baut keine Verbindung auf.

### 3.1 Suche

#### `splunk_search`

> Run an SPL search on Splunk and wait for the results. Use this for most questions about log data. Always set a time range and keep `max_rows` small; prefer aggregating in SPL (`stats`, `timechart`, `top`) over fetching raw events. For searches expected to run longer than about two minutes use `splunk_start_search` instead.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `query` | string | ja | SPL. Beginnt mit `search`, `|` oder einem Suchausdruck; fehlt `search`/`|`, wird `search ` vorangestellt |
| `earliest` | string | nein | Default `SPLUNK_DEFAULT_EARLIEST` |
| `latest` | string | nein | Default `now` |
| `max_rows` | integer | nein | Default 100, gedeckelt auf `SPLUNK_MAX_ROWS` |
| `app` | string | nein | App-Kontext für Macros/Lookups, Default `SPLUNK_APP` |
| `fields` | string[] | nein | Nur diese Felder zurückgeben |
| `sourcetype` | string | nein | Überschreibt den Standard-Sourcetype der Umgebung (1.9) |
| `host` | string | nein | Überschreibt den Standard-Host der Umgebung (1.9) |
| `ignore_default_scope` | boolean | nein | `true` = ohne Standard-Sourcetype/-Host suchen; Default `false` |
| `include_excluded` | boolean | nein | `true` = Ausschlussfilter (1.10, z. B. `/actuator`) für diesen Aufruf abschalten; Default `false` |

- **Endpunkt:** `POST /servicesNS/-/{app}/search/v2/jobs` mit `exec_mode=normal`, dann Polling des Jobs, dann `GET …/search/v2/jobs/{sid}/results`.
- **Rückgabe:** `data` = Ergebniszeilen; `meta` = `sid`, `count`, `total` (`resultCount`), `scan_count`, `run_duration_s`, `earliest`, `latest`, `truncated`, `effective_query`, `scope_applied`, `excluded`, `web_url`.
- **Verhalten:** SPL-Guard (4.1) vor dem Absenden. Bei Timeout wird der Job **nicht** abgebrochen, sondern `sid` plus Hinweis auf `splunk_get_job_status` zurückgegeben.

#### `splunk_start_search`

> Start a long-running SPL search in the background and return its job id (`sid`) immediately. Follow up with `splunk_get_job_status` and then `splunk_get_job_results`.

Parameter wie `splunk_search` ohne `max_rows` und `fields`. Rückgabe: `{ sid }`.

#### `splunk_get_job_status`

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

> Parse an SPL query without running it. Use this to check syntax before an expensive search or after a syntax error.

| Parameter | Typ | Pflicht |
|---|---|---|
| `query` | string | ja |
| `app` | string | nein |

- **Endpunkt:** `POST /servicesNS/-/{app}/search/v2/parser` mit `parse_only=true`
- **Rückgabe:** `valid`, `commands` (Liste der erkannten Kommandos), `risky_commands` (laut 4.1), `messages`.

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

> List the sourcetypes, hosts or sources present in an index, with event counts and last-seen time. Use this after `splunk_list_indexes` to learn what kind of data an index contains.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `index` | string | nein | Default: Standard-Index der Umgebung, sonst die Standard-Indizes der Rolle |
| `kind` | string enum `sourcetypes` \| `hosts` \| `sources` | nein | Default `sourcetypes` |
| `earliest` | string | nein | Default `-7d` |
| `max_rows` | integer | nein | Default 100 |

- **Umsetzung:** `| metadata type={kind} [index={index}] | sort - totalCount | head {max_rows}`
- **Rückgabe:** `name`, `total_count`, `first_time`, `last_time`.

#### `splunk_get_field_summary`

> Show which fields exist in a slice of data, how often they occur and example values. Use this before writing a search that filters or groups by fields you have not seen yet.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `index` | string | nein | Default: Standard-Index der Umgebung, sonst die Standard-Indizes der Rolle |
| `sourcetype` | string | nein | Default: Standard der Umgebung |
| `host` | string | nein | Default: Standard der Umgebung |
| `earliest` | string | nein | Default `-1h` |
| `sample_size` | integer | nein | Default 5000 Events |
| `max_fields` | integer | nein | Default 50 |

- **Umsetzung:** `search index=… sourcetype=… | head {sample_size} | fieldsummary maxvals=5 | sort - count | head {max_fields}`
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

> Run an existing saved search now and return its results. Alert actions are not triggered.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `name` | string | ja | |
| `app` | string | nein | |
| `earliest` | string | nein | Überschreibt das gespeicherte Zeitfenster |
| `latest` | string | nein | |
| `max_rows` | integer | nein | Default 100 |

- **Endpunkt:** `POST …/saved/searches/{name}/dispatch` mit `trigger_actions=0`, danach wie `splunk_search`.
- Der SPL-Guard gilt auch hier, geprüft wird die gespeicherte SPL.

#### `splunk_list_fired_alerts`

> List alerts that have triggered recently, with trigger time and severity.

| Parameter | Typ | Pflicht | Beschreibung |
|---|---|---|---|
| `name` | string | nein | Nur dieser Alert |
| `max_rows` | integer | nein | Default 50 |

- **Endpunkte:** `GET /services/alerts/fired_alerts` bzw. `…/fired_alerts/{name}`
- **Rückgabe ohne `name`:** je Alert `alert_name`, `triggered_count`, `app`.
- **Rückgabe mit `name`:** die einzelnen Auslösungen mit `trigger_time`, `severity`, `sid`.

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
- Lookup-**Inhalte** werden per `splunk_search` mit `| inputlookup <name>` gelesen.

### 3.5 KV Store

#### `splunk_query_kvstore`

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

### 4.1 SPL-Guard

Vor jedem Dispatch wird die Query serverseitig geprüft (Tokenisierung an `|`, Subsearches in `[...]` eingeschlossen). Ohne `SPLUNK_ALLOW_RISKY_SPL=true` werden diese Kommandos mit `RISKY_SPL` abgelehnt:

`delete`, `collect`, `mcollect`, `meventcollect`, `outputlookup`, `outputcsv`, `sendemail`, `sendalert`, `script`, `run`, `runshellscript`, `dump`, `tscollect`, `rest` mit schreibender Methode, `map` (unbegrenzte Subsearch-Schleifen), `dbxquery`, `dbxoutput`.

Zusätzlich:

- Jede Suche bekommt ein Zeitfenster; `earliest=0` / All-Time nur, wenn das Modell es ausdrücklich setzt und die Antwort einen Hinweis trägt.
- Bei gesetzter `SPLUNK_ALLOWED_INDEXES` werden Queries abgelehnt, die andere Indizes oder `index=*` nennen.
- Der Guard ist eine Komfortschranke, kein Sicherheitsmodell. **Die eigentliche Grenze ist die Splunk-Rolle des Tokens** (siehe 4.2).

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

---

## 5. Fehlercodes

| Code | Bedeutung | Hinweis an das Modell |
|---|---|---|
| `AUTH_FAILED` | Login abgelehnt (Passwort falsch/abgelaufen, Konto gesperrt) | Benutzer muss Passwort neu verschlüsseln; nicht erneut versuchen |
| `DECRYPT_FAILED` | `SPLUNK_PASSWORD_ENC` passt nicht zu `SPLUNK_SECRET` | `node dist/cli.js encrypt` neu ausführen |
| `FORBIDDEN` | 403, Capability oder Index fehlt | `splunk_get_current_user` aufrufen |
| `NOT_FOUND` | Objekt oder `sid` unbekannt | Liste abrufen und Namen prüfen |
| `SPL_SYNTAX` | Parser-Fehler | Splunk-Meldung lesen, Query korrigieren |
| `RISKY_SPL` | Vom Guard geblockt | Kommando entfernen; Benutzer informieren |
| `INDEX_NOT_ALLOWED` | Index nicht in der Allowlist | Erlaubte Indizes werden mitgeliefert |
| `JOB_NOT_DONE` | Ergebnisse noch nicht verfügbar | `splunk_get_job_status` |
| `JOB_FAILED` | Suchjob ist fehlgeschlagen | Splunk-Meldungen lesen, Query korrigieren |
| `INVALID_ARGUMENT` | Parameter ungültig (z. B. KV-Store-Query kein JSON) | Parameter korrigieren |
| `TLS_FINGERPRINT_MISSING` | Modus `pinned` ohne hinterlegten Fingerprint | `node dist/cli.js fingerprint <NAME> <url>` ausführen |
| `CONFIG_ERROR` | Konfiguration unvollständig oder fehlerhaft | Server startet nicht; Meldung auf stderr |
| `TIMEOUT` | Wartezeit überschritten, Job läuft weiter | `sid` weiterverwenden |
| `TLS_ERROR` | Zertifikat nicht vertrauenswürdig (`verify`) | `SPLUNK_CA_CERT` setzen oder auf `pinned` wechseln |
| `TLS_FINGERPRINT_MISMATCH` | Zertifikat passt nicht zum hinterlegten Fingerprint | `node dist/cli.js fingerprint <NAME> <url>` neu ausführen, Benutzer informieren |
| `HTTP_NOT_ALLOWED` | `http://`-URL ohne `SPLUNK_ALLOW_HTTP` | Flag setzen oder `https://` verwenden |
| `UNREACHABLE` | Host/Port nicht erreichbar | `SPLUNK_URL_<NAME>` und Port prüfen |
| `UNKNOWN_ENVIRONMENT` | Umgebung nicht konfiguriert | Gültige Namen werden mitgeliefert; Benutzer fragen |
| `LOGIN_BLOCKED` | Nach `AUTH_FAILED` sind Logins gesperrt | Passwort neu verschlüsseln, Server neu starten |

---

## 6. Typischer Ablauf (für `GEMINI.md`)

```text
0. Umgebung klären (vom Benutzer genannt, sonst nachfragen)
1. splunk_list_indexes                → Wo liegen die Daten?
2. splunk_list_sourcetypes(index)     → Welche Datenarten?
3. splunk_get_field_summary(index, …) → Welche Felder?
4. splunk_search(query, earliest, …)  → Aggregiert fragen, kleines max_rows
5. Bei truncated=true                 → Query enger fassen oder splunk_get_job_results(offset)
```

Der Server liefert diesen Ablauf beim Verbinden als MCP-`instructions` mit. Eigene Ergänzungen können zusätzlich in eine `GEMINI.md` geschrieben werden.

### 6.1 Was Gemini selbst herausfindet und was nicht

| Frage | Quelle | Automatisch? |
|---|---|---|
| Welche Indizes gibt es? | `splunk_list_indexes` | ja |
| Welche Hosts / Sourcetypes / Sources liefern in einen Index? | `splunk_list_sourcetypes` mit `kind` | ja |
| Welche Felder gibt es? | `splunk_get_field_summary` | ja |
| Welcher Index / Host gehört zu welchem **Projekt**? | Splunk kennt kein „Projekt" | **nein** – nur über Namensschema oder `GEMINI.md` |

Das Wissen bleibt nicht zwischen Sitzungen erhalten. Feste Zuordnungen (Projekt → Index, Host-Namensschema, wichtige Sourcetypes und Felder) gehören deshalb in die `GEMINI.md`, z. B.:

```markdown
## Splunk-Umgebung
- Projekt "shop": index=app_shop, Hosts shop-web-*, shop-db-*
- Projekt "billing": index=app_billing, Feld `service` unterscheidet Komponenten
- Firewall-Logs: index=net_fw, sourcetype=pan:traffic
```

---

## 7. Offene Punkte

- [ ] Hostnamen der fünf Umgebungen, App-Name, Sourcetype und Host je Umgebung.
- [ ] Ist 8089 in allen fünf Umgebungen erreichbar (bisher an einer geprüft)?
- [ ] Einzelner Search Head oder Search-Head-Cluster (Jobs sind an den Member gebunden; hinter einem Load Balancer braucht es Sticky Sessions).
- [ ] Wie werden Projekte in Splunk unterschieden (Index, Feld, Host-Namensschema)? Siehe 6.1.
- [ ] Enterprise Security im Einsatz? Dann eigene Tools für Notables sinnvoll.
- [ ] MCP-Resources/Prompts (z. B. `/splunk:investigate` als Slash-Command in der Gemini CLI) als Phase 2.
