# wm-audit — Sicherheitsdatenblatt

Für Security-Review und Freigabeprozess beim Kunden. Jede Zusage verweist auf
die Stelle, die sie umsetzt, und auf den Test, der sie belegt.

| | |
|---|---|
| Version | 1.0.0 (Rust) |
| Stand | 09.10.2026 |
| Lizenz | Apache-2.0 |
| Art | Ein Programm je Plattform mit Startdatei, läuft lokal |
| Plattformen | Windows x86_64, macOS (Apple Silicon und Intel, Universal-Binary), Linux x86_64 (statisch gelinkt) |
| Getestet | macOS Apple Silicon und Linux x86_64: alle Tests; macOS Intel: Golden-Fälle unter Rosetta; Windows: Golden-Fälle des `.exe` unter Wine — die Startdatei `wm-audit-starten.cmd` ist auf echtem Windows noch nicht getestet |

## 1. Zweck und Datenfluss

`wm-audit` liest einen **Export des webMethods API Gateway** (ZIP-Datei oder
entpacktes Verzeichnis) und prüft die darin enthaltene Konfiguration auf
Sicherheitslücken. Es gibt keinen Dienst, keinen Agenten, keine Verbindung zum
Gateway und keine Telemetrie.

```
Export (ZIP/Ordner) ──lesen──▶ wm-audit ──▶ Bericht (stdout oder --output-Datei)
                     nur lesend          kein Netzwerk, keine weiteren Dateien
```

**Bedrohungsmodell.** Der Export gilt als nicht vertrauenswürdig (er könnte
manipuliert sein); der Bericht gilt als weitergebbar (er darf keine Geheimnisse
enthalten). Das Werkzeug läuft mit den Rechten des aufrufenden Benutzers.

## 2. Zusagen und Nachweise

| Nr. | Zusage | Umsetzung | Nachweis |
|---|---|---|---|
| S1 | **Kein Netzwerkzugriff.** | Keine Netzwerk-, TLS- oder Async-Crates im Abhängigkeitsbaum; kein `std::net` im Quelltext. | `deny.toml` (Bann-Liste), `pruefen.sh` (Abhängigkeitsbaum), Test `quelltext_ohne_netzwerk_prozesse_und_unsafe` |
| S2 | **Zugangsdaten werden nie geöffnet.** Einträge unter `PassmanData`, `Keystore`, `Truststore`, `Kerberos` (als Pfadteil oder Präfix `<Name>.`, ohne Groß-/Kleinschreibung) werden weder dekomprimiert noch gelesen, nur gezählt. | `lesen.rs`: Sperrprüfung vor jedem Zugriff auf den Inhalt | Kanarienvögel in den Fixtures; Tests `gesperrte_assets_werden_nie_geoeffnet`, `sperrliste` |
| S3 | **Zugangsdaten in URLs werden geschwärzt.** `http://user:pw@host` erscheint im Bericht als `http://***@host`. | `regeln.rs`: `ohne_zugangsdaten` | Tests `zugangsdaten_in_urls_werden_geschwaerzt`, `zugangsdaten_werden_geschwaerzt` |
| S4 | **Nur lesend.** Der Export bleibt unverändert; ein ZIP wird im Speicher gelesen, nie auf Platte entpackt. Geschrieben wird ausschließlich die mit `--output` genannte Datei. | `lesen.rs`, `main.rs` | Tests `export_wird_nicht_veraendert`, `geschrieben_wird_nur_die_ausgabedatei` |
| S5 | **Keine Prozesse, keine Shell.** | — | Test `quelltext_ohne_netzwerk_prozesse_und_unsafe` |
| S6 | **Speichersicherheit.** Kein `unsafe` im eigenen Code (per Lint verboten); `unwrap`, `expect`, `panic` per Clippy verboten; Überlaufprüfung auch im Release. | `Cargo.toml` (`[lints]`, `[profile.release]`) | `cargo clippy -- -D warnings` in `pruefen.sh` |
| S7 | **Schutz vor ZIP-Bomben.** Höchstens 32 MiB je Asset, 512 MiB gelesene Daten insgesamt, 50 000 Einträge. Gelesen wird begrenzt, unabhängig von den Größenangaben im ZIP-Header. | `lesen.rs`: `Grenzen`, `begrenzt_lesen` | Test `zip_bombe_wird_nicht_ausgepackt` (256 MiB, Abbruch nach 1 MiB), `grenze_*` |
| S8 | **Schutz vor JSON-Bomben.** Verschachtelung über 100 Ebenen wird vor dem Parsen erkannt; kein Stapelüberlauf. | `werte.rs`: `verschachtelung` | Test `json_tiefenbombe_ueberlaeuft_keinen_stapel` (1 Mio. Ebenen) |
| S9 | **Mehrdeutige Archive werden abgelehnt.** Zwei Einträge mit gleichem Namen (ein bekannter Trick, verschiedenen Werkzeugen verschiedene Inhalte zu zeigen) führen zum Abbruch. | `lesen.rs`: `zentralverzeichnis_zaehlen` | Test `doppelte_eintragsnamen_werden_abgelehnt` |
| S10 | **Nur Stored/Deflate.** Verschlüsselte oder anders komprimierte Einträge werden nicht gelesen und im Bericht ausgewiesen. | `lesen.rs`, Crate-Features in `Cargo.toml` | Golden-Fall `robust-zip` |
| S11 | **Symlinks werden nicht verfolgt**, FIFOs und Geräte nie geöffnet. | `lesen.rs`: `wandern` | Tests `symlinks_werden_nicht_verfolgt`, `fifo_wird_nicht_geoeffnet` |
| S12 | **Transparenz.** Jede übersprungene Datei steht mit Grund im Bericht; die Zahl nicht geöffneter gesperrter Einträge wird genannt; der Bericht enthält den SHA-256 der geprüften ZIP-Datei und nur den Dateinamen der Quelle (keine Benutzerpfade). | `bericht.rs` | Golden-Files |
| S13 | **Deterministisch.** Gleicher Export → byte-gleicher Bericht, stabile Befund-IDs. | sortierte Ausgabe, keine Zeitstempel | Golden-Files |
| S14 | **Schlanke, geprüfte Lieferkette.** 23 Crates, nur von crates.io, nur MIT/Apache-2.0/Zlib, kein C-Code, Versionen über `Cargo.lock` fixiert. | `Cargo.toml`, `Cargo.lock`, `deny.toml` | `cargo deny check`, `cargo audit` (RustSec: 0 Befunde am 13.10.2026), SBOM `wm-audit.cdx.json` |
| S15 | **Reproduzierbarer Build ohne lokale Pfade.** Zwei Builds aus sauberem Zustand sind bitgleich; das Binary enthält keine Benutzer- oder Build-Pfade. | `bauen.sh` (`--remap-path-prefix`), LTO, `strip` | `bauen.sh` bricht bei Pfaden im Binary ab; SHA-256 macOS arm64 (Version 1.0.0 mit JUnit-Ausgabe): `2088d9ffb31250ccc9c9abff43bd85fab7f2fbab01ec077f20125ba5fe51ba0b` |
| S16 | **Fachlich gleich mit einer unabhängigen Referenz-Implementierung.** | — | 15 Golden-Fälle byte-identisch (Text, JSON, HTML, JUnit-XML); 10 000 zufällig erzeugte Exporte differenziell verglichen; 3 öffentliche Software-AG-Exporte |
| S17 | **HTML-Bericht ohne Nachladen und ohne Code-Einschleusung.** Eine Content-Security-Policy (`default-src 'none'`) verbietet jede Verbindung; Werte aus dem Export werden nur als Text eingesetzt, `<` im Datenblock maskiert. Die Anleitungen folgen der IBM-Dokumentation webMethods API Gateway 10.15/11.1. | `bericht.html`, `bericht.rs`: `als_html` | Tests `html_bericht_laesst_keinen_code_aus_dem_export_durch`, `html_vorlage_laedt_nichts_nach`, `html_vorlage_gleich_referenz` |

## 3. Abhängigkeiten

| Crate | Zweck | Lizenz |
|---|---|---|
| `serde_json` | JSON lesen und Bericht schreiben | MIT/Apache-2.0 |
| `zip` | ZIP lesen — nur Deflate; ohne Verschlüsselung, bzip2, lzma, zstd | MIT |
| `flate2` + `zlib-rs` | Deflate, reine Rust-Implementierung | MIT/Apache-2.0, Zlib |
| `sha2` | SHA-256 der geprüften ZIP-Datei | MIT/Apache-2.0 |
| `sha1` | Stabile Befund-IDs, kompatibel zu bestehenden Berichten — **keine** Sicherheitsfunktion | MIT/Apache-2.0 |

Transitiv: `block-buffer`, `cfg-if`, `cpufeatures`, `crc32fast`, `crypto-common`,
`digest`, `equivalent`, `hashbrown`, `hybrid-array`, `indexmap`, `itoa`, `libc`,
`memchr`, `serde_core`, `typed-path`, `typenum`, `zmij`. Vollständig mit
Versionen und Prüfsummen: `Cargo.lock` und die SBOM.

## 4. Funktionsumfang

**Prüfregeln** (Befund = Feststellung aus der Konfiguration, kein Laufzeittest):

| Regel | Befund | Schwere | Sicherheit | OWASP API |
|---|---|---|---|---|
| `gw.anonymous_allowed` | Identify-Policy lässt anonymen Zugriff zu | Critical | belegt | API2 |
| `gw.no_identify_policy` | API ohne Identify-and-Authorize-Policy | High | belegt | API2 |
| `gw.identify_or` | Identifikationsverfahren ODER-verknüpft | High | belegt | API2 |
| `gw.http_allowed` | Gateway nimmt unverschlüsseltes HTTP an | High | belegt | API8 |
| `gw.plaintext_backend` | Routing auf ein Klartext-Backend (inkl. Alias-Auflösung) | High | belegt | API8 |
| `gw.application_identity_only` | Nur Anwendungs-, keine Benutzeridentität | Medium | wahrscheinlich | API2 |
| `gw.pass_security_headers` | Security-Header gehen ans Backend | Medium | wahrscheinlich | API8 |
| `gw.no_traffic_limit` | Keine Mengen- oder Größenbegrenzung | Medium | wahrscheinlich | API4 |
| `gw.throttle_long_window` | Kontingent über einen Tag oder länger bremst keine Lastspitzen | Low | wahrscheinlich | API4 |
| `gw.log_invocation` | Anfragen werden protokolliert | Low | wahrscheinlich | API8 |

**Gelesen werden** API-Definitionen, Policies mit ihrer Stage-Zuordnung
(`policyEnforcements` — nicht zugeordnete Aktionen zählen nicht), Policy-Aktionen
und einfache Aliase. Mehrere Umgebungen in einem Archiv (`test/`, `prod/`) werden
getrennt ausgewertet.

**Ausdrücklich nicht bewertet** — statisch nicht entscheidbar, im Bericht
benannt: Abweisung erfundener API-Keys, JWT-Signaturprüfung, objektbezogene
Berechtigung (BOLA), Rollendurchsetzung, Trust-Header-Fälschung, globale
Threat-Protection, Antwort-Header, tatsächliches CORS-Verhalten.

**Lastgrenzen:** Je Traffic-Optimization-Policy werden erlaubte Aufrufe, Intervall, `consumerIds` und die Meldung bei Überschreitung ausgelesen (Felder nach der offiziellen IBM-Postman-Collection; nicht eindeutig Lesbares bleibt leer). Der HTML-Bericht enthält dazu einen Lastrechner: Er zeigt für ein Lastprofil, was durchgeht, was mit 429 (Kontingent) und was mit 503 (Bulkhead) abgelehnt wird. Das Modell stützt sich nur auf belegte Aussagen der IBM-Dokumentation; was nicht im Export steht (Knoten, Bulkhead, Antwortzeit), fragt der Rechner als Annahme ab. Er rechnet lokal im Browser, ohne Verbindung nach außen (S17).

**Ausgabe:** HTML-Bericht mit Aufgabenliste und Anleitung je Befund (`--html`), Text, JSON (`wm-audit-bericht/1`) oder JUnit-XML (`--junit`: je API eine Testsuite, je Prüfregel ein Testfall; geprüft gegen das JUnit-Schema des Jenkins-xUnit-Plugins); `--fail-on` für CI-Pipelines. Alle Optionen: [DOKUMENTATION.md](DOKUMENTATION.md)

## 5. Bekannte Grenzen

- Getestet mit konstruierten Exporten und drei öffentlichen Software-AG-Beispielen
  (Format 10.x). Ein echter, anonymisierter Kundenexport wurde noch nicht geprüft.
- Klartext-Routing wird nur für `straightThroughRouting` bewertet; bei anderen
  Routing-Arten macht die Regel keine Aussage.
- Policies auf Teilbereichen einer API (Scopes) und globale Policies werden nicht
  unterschieden: eine Identify-Policy auf einem Scope gilt für die ganze API.
- Aliase werden nur vom Typ `simple` und nicht rekursiv aufgelöst.
- Die Programme sind nicht mit einem Hersteller-Zertifikat signiert (Apple Developer ID,
  Windows Authenticode); Prüfsummen aller Dateien stehen in `SHA256SUMS` des Release-Pakets.
- Wird eine Datei des Exports während des Laufs durch einen anderen Dateityp
  ersetzt, kann das Lesen blockieren. Das setzt Schreibrechte auf den Export voraus
  und liegt außerhalb des Bedrohungsmodells.

## 6. Selbst prüfen

```bash
./pruefen.sh            # Formatierung, Clippy, Tests, cargo-deny, cargo-audit, SBOM, Build
./bauen.sh              # Release-Build, gibt den SHA-256 des Binaries aus
```
