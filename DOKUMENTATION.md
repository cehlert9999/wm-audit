# wm-audit – Dokumentation

Version 1.0.0 · Stand 13.10.2026 · Online: https://leanofy.de/wm-audit/dokumentation ·
Quelltext: https://github.com/cehlert9999/wm-audit

wm-audit liest den Export eines webMethods API Gateway und prüft die Konfiguration, die dort
tatsächlich greift. Diese Dokumentation beschreibt Eingabe, Kommandozeile, Exit-Codes, die
Berichtsformate einschließlich JUnit-XML, alle Prüfregeln und die Grenzen des Werkzeugs.

<!-- Inhalt gleich halten mit der Webseite (leanofy-v2: src/pages/SectestxWmAuditDocsPage.tsx). -->

## Inhalt

1. [Überblick](#1-überblick)
2. [Programme und Start](#2-programme-und-start)
3. [Den Export erstellen](#3-den-export-erstellen)
4. [Kommandozeile](#4-kommandozeile)
5. [Exit-Codes](#5-exit-codes)
6. [CI/CD und JUnit](#6-cicd-und-junit)
7. [Berichtsformate](#7-berichtsformate)
8. [Prüfregeln](#8-prüfregeln)
9. [Was gelesen wird](#9-was-gelesen-wird)
10. [Lastgrenzen und Lastrechner](#10-lastgrenzen-und-lastrechner)
11. [Was nicht geprüft wird](#11-was-nicht-geprüft-wird)
12. [Sicherheit und Freigabe](#12-sicherheit-und-freigabe)
13. [Externe Bibliotheken](#13-externe-bibliotheken)
14. [Versionen](#14-versionen)

---

## 1. Überblick

Eine API-Spezifikation beschreibt, was eine Schnittstelle tun soll. Der Export des Gateways
beschreibt, was sie tut: welche Policies zugeordnet sind, wohin geroutet wird, welche Protokolle
erlaubt sind. wm-audit wertet diesen Export in einem Lauf aus:

- liest APIs, Policies, Policy-Aktionen und Aliase aus einem ZIP-Archiv oder einem entpackten Ordner,
- berücksichtigt nur Policy-Aktionen, die im Gateway einer Stage zugeordnet sind,
- prüft jede API gegen zehn Regeln und trennt belegte Befunde von Hinweisen,
- liest die Lastgrenzen der Traffic-Optimization-Policies aus,
- schreibt einen Bericht als Text, JSON, HTML oder JUnit-XML und setzt auf Wunsch einen
  Exit-Code für die Pipeline.

**Was wm-audit nicht tut:** Es stellt keine Verbindung her und sendet keine Anfrage an Ihre APIs.
Es verändert den Export nicht und entpackt kein ZIP auf die Platte. Passwörter und Schlüssel
(PassmanData, Keystore, Truststore, Kerberos) öffnet es nie. Ob eine Policy im Betrieb greift,
zeigt erst ein Test gegen die laufende API – diese Fragen nennt der Bericht, statt sie zu bewerten.

## 2. Programme und Start

| Plattform | Programm | Startdatei (ohne Kommandozeile) |
|---|---|---|
| Windows (x86-64) | `wm-audit.exe` | `start/wm-audit-starten.cmd` – beim ersten Start „Weitere Informationen“ → „Trotzdem ausführen“ |
| macOS (Apple Silicon und Intel) | `wm-audit` | `wm-audit.app` – beim ersten Start Rechtsklick → Öffnen; ab macOS 15 unter Systemeinstellungen → Datenschutz & Sicherheit freigeben |
| Linux (x86-64, statisch gelinkt) | `wm-audit` | `start/wm-audit-starten.sh` – Dateiauswahl mit zenity, falls installiert |

Mit Startdatei: den Export auf die Datei ziehen oder sie doppelklicken und eine ZIP-Datei
auswählen. Der HTML-Bericht wird unter `Dokumente/wm-audit Berichte/` als
`Bericht_<Export>_<Datum>_<Uhrzeit>.html` gespeichert und im Browser geöffnet.

Das Programm ist eine einzelne Datei; eine Installation oder Laufzeitumgebung ist nicht nötig.

**Selbst bauen** (Rust ab 1.88):

```bash
cargo build --release --locked   # Programm: target/release/wm-audit
cargo test --locked              # Prüffälle und Sicherheitstests
./pruefen.sh                     # alle Prüfungen in einem Lauf (siehe Abschnitt 12)
./bauen-linux.sh                 # Linux x86_64 statisch, in Docker
./bauen-windows.sh               # Windows x86_64, in Docker; Prüffälle unter Wine
```

## 3. Den Export erstellen

Laut IBM-Dokumentation exportieren Sie APIs im API Gateway so:

1. In der Titelleiste **APIs** öffnen.
2. Eine API: das Export-Symbol neben der API anklicken. Mehrere APIs: die Kästchen der APIs
   markieren, das Zahnrad-Symbol anklicken und **Export** wählen.
3. Optional „Include applications“ und weitere Optionen wählen, dann **Export**. Der Browser
   bietet das Archiv zum Speichern an.

Quelle: [IBM – Exporting APIs](https://www.ibm.com/docs/en/SSAQ10_10.15.0/apigateway_spg/ta-exporting_api.html).
Übergeben Sie wm-audit das Archiv unverändert oder den entpackten Ordner.

**Mehrere Umgebungen:** Liegen Exporte in Unterordnern, etwa `test/` und `prod/`, liest wm-audit
jede API mit den Policies und Aliasen aus ihrem eigenen Teilbaum. Dieselbe API aus Test und
Produktion wird getrennt geprüft; eine Policy aus der Produktion verdeckt keine Lücke im Test.

## 4. Kommandozeile

### Aufruf

```
wm-audit EXPORT [--json | --html | --junit] [--output DATEI] [--fail-on SCHWERE]
```

Unter Windows heißt das Programm `wm-audit.exe`. Optionen dürfen vor oder nach dem Export stehen.
Wird eine Option mehrfach angegeben, gilt der letzte Wert. Optionen werden nur ausgeschrieben
erkannt; Abkürzungen wie `--js` sind ein Aufruffehler.

Ausgabe von `wm-audit --help`:

```
usage: wm-audit [-h] [--json | --html | --junit] [--output OUTPUT] [--fail-on {critical,high,medium,low,info}] [--version] export

Statische Security-Analyse eines webMethods-API-Gateway-Exports.

positional arguments:
  export                Export als ZIP-Datei oder entpacktes Verzeichnis

options:
  -h, --help            Hilfe anzeigen und beenden
  --json                Bericht als JSON ausgeben
  --html                Bericht als HTML-Datei mit Aufgabenliste (für Menschen)
  --junit               Bericht als JUnit-XML für CI-Systeme (Jenkins, GitLab …)
  --output, -o OUTPUT   Bericht in diese Datei schreiben statt auf stdout
  --fail-on {critical,high,medium,low,info}
                        Exit-Code 1, wenn ein belegter Befund mindestens diese Schwere hat
  --version             Version anzeigen und beenden
```

### Optionen

| Option | Standard | Wirkung |
|---|---|---|
| `EXPORT` | Pflicht, genau einer je Aufruf | Ein Ordner wird als entpackter Export gelesen, jede andere Datei als ZIP-Archiv – unabhängig von der Dateiendung. |
| (keine Formatoption) | Standard | Bericht als Text. |
| `--json` | – | Bericht als JSON im Format `wm-audit-bericht/1`. |
| `--html` | – | Bericht als HTML-Datei mit Aufgabenliste, Anleitungen und Lastrechner. Mit `--output` verwenden. |
| `--junit` | – | Bericht als JUnit-XML für CI-Systeme, siehe [Abschnitt 6](#6-cicd-und-junit). |
| `--output DATEI`, `-o DATEI`, `--output=DATEI` | Standardausgabe | Schreibt den Bericht in diese Datei. Eine vorhandene Datei wird überschrieben, der Ordner muss existieren. |
| `--fail-on SCHWERE`, `--fail-on=SCHWERE` | aus | Exit-Code 1, wenn mindestens ein **belegter** Befund diese Schwere oder eine höhere hat. Werte: `critical`, `high`, `medium`, `low`, `info`. Bestimmt im JUnit-Bericht, welche Befunde als Fehler zählen; Text, JSON und HTML ändern sich nicht. |
| `--version` | – | Gibt `wm-audit 1.0.0` aus und endet mit 0. |
| `-h`, `--help` | – | Gibt die Hilfe aus und endet mit 0. |
| `--` | – | Beendet die Optionen; alles danach gilt als Pfad (für Exporte, deren Name mit `-` beginnt). |

### Regeln für Ausgabe und Formate

- `--json`, `--html` und `--junit` schließen sich gegenseitig aus. Ohne eine davon entsteht Text.
- Der Bericht ist immer UTF-8. Fehlermeldungen gehen auf die Fehlerausgabe, nie in den Bericht.
- Außer der Ausgabedatei schreibt wm-audit nichts: keine temporären Dateien, keine Logs, keine
  Konfiguration.

### Keine Konfigurationsdatei, keine Umgebungsvariablen

wm-audit liest keine Konfigurationsdatei und keine Umgebungsvariablen. Das Verhalten hängt allein
von den Argumenten und dem Export ab: gleicher Export, gleiche Optionen, byte-gleicher Bericht.
Die Grenzen gegen manipulierte Exporte sind fest eingebaut:

| Grenze | Wert | Bei Überschreitung |
|---|---|---|
| Einträge im ZIP bzw. Dateien im Ordner | 50.000 | Abbruch, Exit-Code 2 |
| Entpackte Asset-Daten insgesamt | 512 MiB | Abbruch, Exit-Code 2 |
| Größe einer Asset-Datei | 32 MiB | Datei übersprungen (`zu_gross`) |
| Verschachtelungstiefe von JSON | 100 | Datei übersprungen (`zu_tief`) |

### Beispiele

```bash
# Bericht mit Aufgabenliste und Lastrechner
wm-audit gateway-export.zip --html -o bericht.html

# Entpackter Export, JSON in eine Datei
wm-audit ./export-ordner --json -o bericht.json

# Gate in der Pipeline: Exit 1 bei belegtem Befund ab "high"
wm-audit gateway-export.zip --fail-on high

# JUnit-XML für Jenkins, GitLab oder Azure DevOps
wm-audit gateway-export.zip --junit -o wm-audit-junit.xml --fail-on high

# Windows (PowerShell oder cmd)
wm-audit.exe C:\Exporte\gateway-export.zip --html -o bericht.html
```

## 5. Exit-Codes

| Code | Bedeutung |
|---|---|
| `0` | Export gelesen, Bericht geschrieben. Gilt auch mit Befunden, solange `--fail-on` nicht ausgelöst hat, und für einen Export ohne API. |
| `1` | Export gelesen, Bericht geschrieben, und `--fail-on` hat ausgelöst: mindestens ein belegter Befund mit der angegebenen oder einer höheren Schwere. |
| `2` | Kein Bericht. **Aufruffehler:** unbekannte Option, fehlender Wert, ungültige Schwere, kein oder ein zweiter Export, mehrere Formatoptionen – dann folgt auf der Fehlerausgabe die Hilfe und `wm-audit: error: …`. **Lesefehler:** Pfad nicht gefunden, keine gültige ZIP-Datei, doppelte Eintragsnamen im ZIP, mehr als 50.000 Einträge, mehr als 512 MiB entpackte Asset-Daten. **Schreibfehler:** Ausgabedatei nicht schreibbar. Meldung jeweils als `wm-audit: …` auf der Fehlerausgabe. |

Die Meldungen im Wortlaut, zum Beispiel:

```
wm-audit: Export nicht gefunden: gibtsnicht.zip
wm-audit: error: --json, --html und --junit schließen sich gegenseitig aus
wm-audit: error: --fail-on: ungültige Schwere "hoch"
wm-audit: error: unbekannte Option: --jso
wm-audit: error: nur ein Export je Aufruf
```

**Tipp für Pipelines:** Ein Export ohne API ist kein Fehler (Exit-Code 0). Wer einen falschen Pfad
oder ein leeres Archiv ausschließen will, prüft `zusammenfassung.apis_gelesen` im JSON bzw. die
Eigenschaft `apis_gelesen` im JUnit-Bericht.

## 6. CI/CD und JUnit

Mit `--junit` schreibt wm-audit einen Testbericht, den Jenkins, GitLab, Azure DevOps und andere
CI-Systeme anzeigen. Jede API ist eine Testsuite, jede Prüfregel ein Testfall: Für 100 APIs
entstehen 1.000 Testfälle aus den Prüfregeln.

### Wann ein Testfall fehlschlägt

- **Ohne `--fail-on`:** Jeder Befund, der die API trifft, ist ein Fehler – belegte Befunde wie
  Hinweise. Der Exit-Code bleibt 0.
- **Mit `--fail-on SCHWERE`:** Fehler sind genau die Befunde, die auch Exit-Code 1 auslösen:
  belegt und mindestens diese Schwere. Alle übrigen Befunde stehen im Testfall unter
  `system-out`; der Testfall gilt als bestanden.
- Zusammengefasste Befunde (eine Regel trifft mehr als die Hälfte der APIs) erscheinen bei jeder
  betroffenen API.
- Dieselbe API aus mehreren Umgebungen ergibt eine Testsuite; die Befunde beider Umgebungen
  stehen darin.

### Aufbau

| Element | Inhalt |
|---|---|
| `testsuites` | `name="wm-audit"`; `tests` und `failures` über alle Suiten; `errors` immer 0. |
| Suite `Export` | Eigenschaften des Laufs: `werkzeug`, `quelle`, `art`, `sha256` (nur bei ZIP), `fail_on` (falls gesetzt), `apis_gelesen`, `apis_eindeutig`, `gesperrt`, `uebersprungen`. Dazu je übersprungener Datei ein Testfall als `skipped`; Name ist der Pfad im Export, `message` der Grund. |
| Suite `API: Name Version` | Je API ein Testfall pro Prüfregel, also 10. `classname` ist `wm-audit.` plus Name und Version, Punkte durch `_` ersetzt (sonst teilt Jenkins am Punkt in Paket und Klasse). `name` ist die Regel-ID und bleibt über Läufe stabil – so führt das CI-System Verläufe je Regel und API. |
| `failure` | `type` ist die Schwere, `message` der Titel des Befunds; der Text nennt Schwere und Einstufung, Begründung, Empfehlung und Fundstelle im Export. Treffen mehrere Befunde derselben Regel eine API, stehen sie in einem `failure`, `type` ist die höchste Schwere. |
| Suite `Statisch nicht prüfbar` | Die acht Fragen, die kein Export beantwortet, als `skipped` mit Begründung. |

Das XML enthält keine Zeitstempel und keine Laufzeiten: Derselbe Export ergibt dieselbe Datei.
Zeichen, die XML 1.0 nicht erlaubt, werden durch U+FFFD ersetzt; alles andere wird maskiert.
Geprüft ist das Format gegen das JUnit-Schema des Jenkins-xUnit-Plugins (`junit-10.xsd`).

```xml
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="wm-audit" tests="109" failures="7" errors="0">
  <testsuite name="Export" tests="1" failures="0" errors="0" skipped="1">
    <properties>
      <property name="werkzeug" value="wm-audit 1.0.0"/>
      <property name="quelle" value="gateway-export.zip"/>
      <property name="fail_on" value="high"/>
      <property name="apis_gelesen" value="10"/>
      …
    </properties>
    <testcase classname="wm-audit.export" name="…/PolicyAction.c2-verwaist">
      <skipped message="nicht_zugeordnet"/>
    </testcase>
  </testsuite>
  <testsuite name="API: AnonymAPI 1.0" tests="10" failures="1" errors="0" skipped="0">
    <testcase classname="wm-audit.AnonymAPI 1_0" name="gw.no_identify_policy"/>
    <testcase classname="wm-audit.AnonymAPI 1_0" name="gw.anonymous_allowed">
      <failure type="critical" message="Identify-Policy erlaubt anonymen Zugriff">[CRITICAL, belegt] …</failure>
    </testcase>
    <testcase classname="wm-audit.AnonymAPI 1_0" name="gw.application_identity_only">
      <system-out>Unterhalb der Schwelle --fail-on high: …</system-out>
    </testcase>
    …
  </testsuite>
  <testsuite name="Statisch nicht prüfbar" tests="8" failures="0" errors="0" skipped="8">
    …
  </testsuite>
</testsuites>
```

### Jenkins

Der erste Aufruf schreibt den HTML-Bericht und endet ohne `--fail-on` mit 0. Der zweite schlägt bei
einem belegten Befund ab „high“ fehl; `post { always }` veröffentlicht Testbericht und HTML-Bericht
trotzdem. Auf Windows-Agents `bat` statt `sh` und `wm-audit.exe` verwenden.

```groovy
pipeline {
  agent any
  stages {
    stage('Gateway-Audit') {
      steps {
        sh 'wm-audit gateway-export.zip --html -o wm-audit-bericht.html'
        sh 'wm-audit gateway-export.zip --junit -o wm-audit-junit.xml --fail-on high'
      }
      post {
        always {
          junit 'wm-audit-junit.xml'
          archiveArtifacts artifacts: 'wm-audit-bericht.html'
        }
      }
    }
  }
}
```

### GitLab CI

```yaml
wm-audit:
  stage: test
  script:
    - wm-audit gateway-export.zip --html -o wm-audit-bericht.html
    - wm-audit gateway-export.zip --junit -o wm-audit-junit.xml --fail-on high
  artifacts:
    when: always
    paths:
      - wm-audit-bericht.html
    reports:
      junit: wm-audit-junit.xml
```

### Azure DevOps

```yaml
steps:
  - script: wm-audit gateway-export.zip --junit -o wm-audit-junit.xml --fail-on high
    displayName: wm-audit
  - task: PublishTestResults@2
    condition: always()
    inputs:
      testResultsFormat: JUnit
      testResultsFiles: wm-audit-junit.xml
```

Den Export liefert ein vorheriger Schritt, etwa ein Export aus der Testumgebung, den Sie im
Repository oder als Artefakt ablegen. wm-audit selbst braucht keinen Zugriff auf das Gateway.

## 7. Berichtsformate

### Text (Standard)

Kopfzeile mit Version, Name der Quelle und Art (`zip` oder `verzeichnis`), bei ZIP der SHA-256,
dann die Zahl der gelesenen APIs, übersprungenen Dateien und nicht geöffneten gesperrten Einträge.
Es folgen die Befunde (Schwere, Einstufung, Regel-ID, betroffene API, Titel), die Lastgrenzen je
API, die übersprungenen Dateien mit Grund und die statisch nicht prüfbaren Fragen.

### HTML

Eine einzelne Datei, die im Browser offline funktioniert: Eine Content-Security-Policy
(`default-src 'none'`) verbietet jede Verbindung, Werte aus dem Export werden nur als Text
eingesetzt. Abschnitte: Ihre Aufgaben (sofort beheben, prüfen und entscheiden), Befunde mit
Schritt-für-Schritt-Anleitung im API Gateway, Erfolgstest und Link zur IBM-Dokumentation,
Lastgrenzen und Lastrechner, gelesene APIs, übersprungene Dateien, statisch nicht Prüfbares.
Die Rohdaten stehen als JSON in der Datei.

### JSON (`wm-audit-bericht/1`)

Schlüssel sortiert, zwei Leerzeichen Einzug, UTF-8 ohne ASCII-Escapes. Die wichtigsten Felder:

| Feld | Inhalt |
|---|---|
| `format` | `"wm-audit-bericht/1"` |
| `werkzeug` | `"wm-audit 1.0.0"` |
| `quelle` | `name` (nur der Dateiname, kein Pfad), `art` (`zip` oder `verzeichnis`), `sha256` (bei ZIP, sonst `null`) |
| `zusammenfassung` | `apis_gelesen`, `apis_eindeutig`, `befunde`, `belegt`, `schwere` (Anzahl je `critical` … `info`), `uebersprungen`, `gesperrt` |
| `apis[]` | `label`, `name`, `version`, `id`, `pfad`, `policies` (zugeordnete Policy-Typen), `lastgrenzen[]` mit `aktion`, `limit`, `intervall`, `einheit`, `consumer`, `meldung` |
| `befunde[]` | `id` (stabil), `check_id`, `title`, `severity`, `confidence` (`belegt` oder `wahrscheinlich`), `bewertet`, `owasp`, `subject`, `reason`, `remediation`, `evidence[]` mit `pointer`, `excerpt`, `note`; bei zusammengefassten Befunden `aggregate_count` und `affected[]` |
| `laufzeit_luecken[]` | `key`, `title`, `owasp`, `why` – die statisch nicht prüfbaren Fragen |
| `uebersprungen[]` | `pfad`, `grund` |

### Gründe für übersprungene Dateien

| Grund | Bedeutung |
|---|---|
| `nicht_zugeordnet` | Policy-Aktion ist keiner Stage zugeordnet und greift im Gateway nicht. |
| `ohne_api` | Policy-Aktion ohne zugehörige API. |
| `ohne_apiname` | API-Datei ohne `apiName`. |
| `kein_json` | Kein gültiges JSON (strikt: kein NaN, keine Kommentare, kein Nachlauf). |
| `kein_objekt` | JSON ist kein Objekt. |
| `kein_utf8` | Kein gültiges UTF-8. |
| `zu_gross` | Größer als 32 MiB. |
| `zu_tief` | JSON tiefer verschachtelt als 100 Ebenen. |
| `lesefehler` | ZIP-Eintrag verschlüsselt, mit fremder Kompression oder falscher Prüfsumme. |
| `symlink` | Symbolischer Link; wird nicht verfolgt. |

## 8. Prüfregeln

**Belegt** heißt: direkt aus der Konfiguration abgelesen; nur belegte Befunde lösen `--fail-on`
aus. **Hinweis** heißt: starkes Anzeichen, das sich statisch nicht abschließend entscheiden lässt.

| Regel | Schwere | Einstufung | OWASP | Befund, wenn … |
|---|---|---|---|---|
| `gw.anonymous_allowed` | critical | belegt | API2 | Identify & Authorize (`evaluatePolicy`) `allowAnonymous` = true hat. |
| `gw.no_identify_policy` | high | belegt | API2 | der API keine Identify-&-Authorize-Policy zugeordnet ist. |
| `gw.identify_or` | high | belegt | API2 | mindestens zwei Identifikationsregeln mit `logicalConnector` = OR verknüpft sind. |
| `gw.application_identity_only` | medium | Hinweis | API2 | alle Identifikationstypen nur eine Anwendung ausweisen (`apiKey`, `hostNameAddress`, `ipAddressRange`). |
| `gw.http_allowed` | high | belegt | API8 | Enable HTTP/HTTPS (`entryProtocolPolicy`) `http` erlaubt. |
| `gw.plaintext_backend` | high | belegt | API8 | das Ziel der Straight-Through-Routing-Policy mit `http://` beginnt (Aliase aufgelöst). Ohne jede Routing-Policy zählt der `nativeEndpoint`; bei anderen Routing-Arten keine Aussage. |
| `gw.pass_security_headers` | medium | Hinweis | API8 | ein `nativeEndpoint` `passSecurityHeaders` = true hat. |
| `gw.no_traffic_limit` | medium | Hinweis | API4 | der API keine Traffic-Optimization-Policy (`throttle`) zugeordnet ist. |
| `gw.throttle_long_window` | low | Hinweis | API4 | alle lesbaren Traffic-Optimization-Grenzen der API über einen Tag oder länger zählen. |
| `gw.log_invocation` | low | Hinweis | API8 | Log Invocation zugeordnet ist. |

**Zusammengefasste Befunde:** Trifft eine Regel mehr als die Hälfte der APIs (gezählt nach Name und
Version), meldet wm-audit sie einmal als „… (durchgängig)“ mit der Liste der betroffenen APIs. Ein
belegter Befund behält dabei seine Schwere; ein Hinweis wird zur Information (`info`).

## 9. Was gelesen wird

- **APIs** (`API.<id>`) mit Name, Version und `nativeEndpoint`.
- **Policies** (`Policy.<id>`) mit ihrer Zuordnung von Stages zu Policy-Aktionen
  (`policyEnforcements`). Eine Aktion zählt nur, wenn sie zugeordnet ist; eine verwaiste Datei
  verdeckt keine Lücke und erscheint als übersprungen.
- **Policy-Aktionen** (`PolicyAction.<id>`) – gehören zur innersten API im Verzeichnisbaum.
- **Aliase** vom Typ `simple`: Routing-Ziele wie `${Backend}/${sys:resource_path}` werden
  aufgelöst; maßgeblich ist der nächstgelegene Alias-Ordner.
- **Nie geöffnet** werden PassmanData, Keystore, Truststore und Kerberos. Sie werden nur gezählt.
  Steht in einer Adresse ein Passwort, ersetzt der Bericht es durch `***`.
- **ZIP-Archive** werden im Speicher gelesen, nicht entpackt. Doppelte Eintragsnamen führen zum
  Abbruch, symbolische Links werden nicht verfolgt.

## 10. Lastgrenzen und Lastrechner

Je Traffic-Optimization-Policy (`throttle`) liest wm-audit die Felder, die IBM in der offiziellen
Postman-Collection verwendet: erlaubte Aufrufe (`throttleRule` mit `requestCount` und Operator
`GT`), `alertInterval`, `alertIntervalUnit` (`minutes`, `hours`, `days`, `weeks`), `consumerIds`
und `alertMessage`. Was nicht eindeutig lesbar ist, bleibt leer.

Der Lastrechner im HTML-Bericht spielt ein Lastprofil gegen eine Grenze durch und zeigt, was
durchgeht, was mit 429 (Kontingent leer) und was mit 503 (Bulkhead) abgelehnt wird. Er stützt
sich nur auf diese IBM-Aussagen:

- Token-Bucket-Verfahren: Ist das Kontingent leer, wird abgelehnt; nach Ablauf des Intervalls ist
  es wieder voll – [Rate limit your APIs](https://www.ibm.com/docs/en/SSAQ10_10.15.0/apigateway_gs/co-ratelimit_api.html)
- Abgelehnt wird mit Status 429 und der Alert Message als Grund – [Testing the API Rate Limit](https://www.ibm.com/docs/en/SSAQ10_10.15.0/apigateway_gs/ta-test_api_ratelimit.html)
- Gezählt wird erst nach der Antwort des Backends; bei gleichzeitigen Aufrufen kann das Limit kurz
  überschritten werden – [Traffic Optimization](https://www.ibm.com/docs/en/SSAQ10_10.15.0/apigateway_ug/re-lmt_throttling_traffic_optimization.html)
- Der Bulkhead begrenzt gleichzeitige Aufrufe je Gateway-Instanz und antwortet darüber mit 503 –
  [Bulkhead](https://www.ibm.com/docs/en/SSAQ10_10.15.0/apigateway_ug/co-bulkhead_pattern.html)

Was nicht im Export steht – Zahl der Gateway-Knoten, Bulkhead-Wert, Antwortzeit des Backends, ob
das Kontingent gemeinsam oder je Anwendung gilt – fragt der Rechner als Annahme ab. Die
Überschreitung durch die späte Zählung schätzt er als Aufrufe pro Sekunde × Antwortzeit; das ist
eine abgeleitete Größenordnung, keine Messung.

## 11. Was nicht geprüft wird

Diese Fragen beantwortet kein Export. Der Bericht nennt sie, bewertet sie aber nie:

- Wird ein erfundener API-Key tatsächlich abgewiesen?
- Wird die JWT-Signatur wirklich geprüft?
- Erreicht ein Aufrufer fremde Objekte (BOLA)?
- Wird die Rollenprüfung durchgesetzt?
- Lässt sich ein Trust-Header fälschen?
- Greift eine globale Threat-Protection?
- Werden Security-Header in Antworten gesetzt?
- Wie verhält sich CORS tatsächlich?

**Bekannte Grenzen:** Global Policies, Plans und Quotas sowie die Denial-of-Service-Regeln der
Threat Protection stehen nicht im API-Export und werden nicht ausgewertet. Policies auf
Teilbereichen einer API (Scopes) werden nicht unterschieden. Klartext-Routing wird für
Straight-Through-Routing bewertet. Die Einheiten „Calendar Week“ und „Calendar Month“ der Traffic
Optimization sind im Export nicht belegt und erscheinen unverändert. Getestet mit konstruierten
Exporten und öffentlichen Software-AG-Beispielen im Format 10.x.

Die Laufzeitfragen beantwortet [sectestx](https://sectestx.leanofy.de), das Werkzeug für
Laufzeittests von Leanofy, mit Tests gegen Ihre Testumgebung.

## 12. Sicherheit und Freigabe

- Geschrieben in Rust, ohne `unsafe`-Code; Abbrüche über `unwrap`, `expect` und `panic` sind per
  Prüfregel ausgeschlossen.
- Keine Netzwerk- oder TLS-Bibliotheken – per Bann-Liste in der Lieferkettenprüfung ausgeschlossen.
- Nur Abhängigkeiten von crates.io unter MIT, Apache-2.0 oder Zlib; Stückliste (SBOM) als CycloneDX.
- Reproduzierbarer Build ohne lokale Pfade im Programm.
- 15 Prüffälle mit erwarteten Ausgaben in allen vier Formaten ([`tests/golden`](tests/golden));
  `cargo test` vergleicht Byte für Byte.

Jede Zusage mit dem Test, der sie belegt: [SICHERHEIT.md](SICHERHEIT.md). `./pruefen.sh`
wiederholt die vollständige Prüfung in einem Lauf – Formatierung, clippy (Warnungen als Fehler),
Tests, cargo-deny, cargo-audit, SBOM und Build ohne lokale Pfade. Es braucht `cargo-deny`,
`cargo-audit` und `cargo-cyclonedx` (`cargo install --locked cargo-deny cargo-audit cargo-cyclonedx`).

## 13. Externe Bibliotheken

wm-audit hat vier direkte Abhängigkeiten von crates.io. Mit deren Abhängigkeiten kommen 23 Crates
ins Programm – unter Linux und Windows 22, denn `libc` braucht nur macOS. Alle Versionen sind über
`Cargo.lock` festgelegt; ein Test prüft, dass diese Liste jedes Paket aus `Cargo.lock` mit seiner
Version nennt.

| Crate | Version | Lizenz | Wozu | Gezogen von |
|---|---|---|---|---|
| `serde_json` | 1.0.151 | MIT oder Apache-2.0 | JSON aus dem Export lesen, Bericht schreiben | direkt |
| `zip` | 9.0.0 | MIT | ZIP-Archive im Speicher lesen | direkt |
| `sha2` | 0.11.0 | MIT oder Apache-2.0 | SHA-256 der geprüften Datei | direkt |
| `sha1` | 0.11.0 | MIT oder Apache-2.0 | stabile Befund-IDs | direkt |
| `serde_core` | 1.0.229 | MIT oder Apache-2.0 | Grundlage von serde_json | serde_json |
| `itoa` | 1.0.18 | MIT oder Apache-2.0 | Ganzzahlen als Text | serde_json |
| `zmij` | 1.0.23 | MIT | Gleitkommazahlen als Text | serde_json |
| `memchr` | 2.8.3 | Unlicense oder MIT | schnelle Suche in Bytes | serde_json, zip |
| `flate2` | 1.1.10 | MIT oder Apache-2.0 | Deflate entpacken | zip |
| `zlib-rs` | 0.6.8 | Zlib | Deflate in reinem Rust, ohne C-Code | flate2 |
| `crc32fast` | 1.5.2 | MIT oder Apache-2.0 | Prüfsummen der ZIP-Einträge | zip |
| `indexmap` | 2.14.2 | Apache-2.0 oder MIT | Verzeichnis der ZIP-Einträge | zip |
| `hashbrown` | 0.17.1 | MIT oder Apache-2.0 | Hashtabelle | indexmap, zip |
| `equivalent` | 1.0.2 | Apache-2.0 oder MIT | Schlüsselvergleich in Tabellen | indexmap, zip |
| `typed-path` | 0.12.3 | MIT oder Apache-2.0 | Pfade der ZIP-Einträge, plattformunabhängig | zip |
| `cfg-if` | 1.0.5 | MIT oder Apache-2.0 | plattformabhängiger Code | crc32fast, zip |
| `digest` | 0.11.3 | MIT oder Apache-2.0 | gemeinsame Schnittstelle der Hash-Funktionen | sha1, sha2 |
| `crypto-common` | 0.2.2 | MIT oder Apache-2.0 | Grundtypen der Hash-Funktionen | digest |
| `block-buffer` | 0.12.1 | MIT oder Apache-2.0 | Blockpuffer der Hash-Funktionen | digest |
| `hybrid-array` | 0.4.15 | MIT oder Apache-2.0 | Feldtypen der Hash-Funktionen | digest, sha1, sha2 |
| `typenum` | 1.20.1 | MIT oder Apache-2.0 | Feldgrößen zur Übersetzungszeit | hybrid-array |
| `cpufeatures` | 0.3.1 | MIT oder Apache-2.0 | Prozessorfunktionen für schnelle Hashes erkennen | sha1, sha2 |
| `libc` | 0.2.190 | MIT oder Apache-2.0 | Systemschnittstelle für cpufeatures, nur macOS | cpufeatures |

Diese Pakete stehen in `Cargo.lock`, werden aber für keine der unterstützten Plattformen gebaut:
`serde_core` führt sie nur unter einer Bedingung, die keine Zielplattform erfüllt.

| Crate | Version | Lizenz |
|---|---|---|
| `serde` | 1.0.229 | MIT oder Apache-2.0 |
| `serde_derive` | 1.0.229 | MIT oder Apache-2.0 |
| `proc-macro2` | 1.0.107 | MIT oder Apache-2.0 |
| `quote` | 1.0.47 | MIT oder Apache-2.0 |
| `syn` | 3.0.6 | MIT oder Apache-2.0 |
| `unicode-ident` | 1.0.26 | (MIT oder Apache-2.0) und Unicode-3.0 |

**Schwachstellen:** `cargo-audit` (RustSec) und `cargo-deny` prüfen jedes Paket aus `Cargo.lock`,
auch die nie gebauten – mit `./pruefen.sh`, in der CI bei jeder Änderung und zusätzlich jeden
Montag, denn neue Schwachstellen tauchen auch ohne Codeänderung auf. Stand 13.10.2026: keine
bekannte Schwachstelle und keine Warnung (ungewartet, unsicher, zurückgezogen).

**Ausgeschlossen:** `deny.toml` lässt nur die Lizenzen MIT, Apache-2.0 und Zlib zu, nur Pakete von
crates.io und verbietet Netzwerk-, TLS- und Async-Bibliotheken (`reqwest`, `hyper`, `h2`, `tokio`,
`async-std`, `mio`, `socket2`, `curl`, `ureq`, `native-tls`, `openssl`, `rustls`, `ring`) sowie
C-Bibliotheken und den C-Compiler-Anschluss (`curl-sys`, `openssl-sys`, `libz-sys`, `bzip2-sys`,
`zstd-sys`, `cc`). Die Stückliste (SBOM) im CycloneDX-Format erzeugt `pruefen.sh`.

## 14. Versionen

| Version | Datum | Änderungen |
|---|---|---|
| 1.0.0 | 12.10.2026 | JUnit-XML (`--junit`) für CI-Systeme; Datenblatt und Dokumentation; eigenes Repository mit Prüfung der Lieferkette in der CI. |
| 0.3.0 | 09.10.2026 | Lastgrenzen je API im Bericht, Lastrechner im HTML-Bericht, neue Regel `gw.throttle_long_window`. |
| 0.2.0 | 09.10.2026 | HTML-Bericht mit Aufgabenliste und Anleitungen nach IBM-Dokumentation; Programme für Windows, macOS und Linux. |

Lizenz: Apache-2.0 · LEANOFY GmbH
