# wm-audit

[![ci](https://github.com/cehlert9999/wm-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/cehlert9999/wm-audit/actions/workflows/ci.yml)

Statische Security-Prüfung für **webMethods-API-Gateway-Exporte** – ein einzelnes Programm für
Windows, macOS und Linux, geschrieben in Rust. Ein Produkt der LEANOFY GmbH.

Ein Gateway-Export sagt, was eine Schnittstelle tatsächlich tut: welche Policies greifen, wohin
geroutet wird, welche Protokolle erlaubt sind. wm-audit liest diese Konfiguration und meldet
Lücken – ohne eine einzige Anfrage an die Schnittstelle, ohne Netzwerk, ohne Passwörter und
Schlüssel im Export zu öffnen. Der Bericht kommt als HTML mit Aufgabenliste und Lastrechner, als
Text, JSON oder JUnit-XML für CI-Systeme.

- **Dokumentation** – Kommandozeile, Exit-Codes, JUnit und Pipelines, Prüfregeln, Formate,
  externe Bibliotheken: **[DOKUMENTATION.md](DOKUMENTATION.md)**
- **Sicherheitseigenschaften** mit Testnachweis je Zusage: [SICHERHEIT.md](SICHERHEIT.md)
- **Produktseite und Datenblatt:** https://leanofy.de/wm-audit

## Aufruf

```bash
wm-audit export.zip                                       # Bericht als Text
wm-audit export.zip --html -o bericht.html                # Aufgabenliste, Anleitungen, Lastrechner
wm-audit export.zip --json                                # JSON (wm-audit-bericht/1)
wm-audit export.zip --junit -o junit.xml --fail-on high   # JUnit-XML für CI, Exit 1 ab "high"
```

Exit-Codes: `0` gelesen · `1` `--fail-on` ausgelöst · `2` Aufruf- oder Lesefehler.
Alle Optionen, Meldungen und Beispiel-Pipelines: [DOKUMENTATION.md](DOKUMENTATION.md#4-kommandozeile).

## Bauen und prüfen

```bash
cargo build --release --locked   # Programm: target/release/wm-audit
cargo test --locked              # Prüffälle und Sicherheitstests
./pruefen.sh                     # fmt, clippy, Tests, cargo-deny, cargo-audit, SBOM, Build
./bauen-linux.sh                 # Linux x86_64 statisch (Docker), Tests im Container
./bauen-windows.sh               # Windows x86_64 (Docker), Prüffälle unter Wine
```

Rust ab 1.88. `pruefen.sh` braucht `cargo-deny`, `cargo-audit` und `cargo-cyclonedx`
(`cargo install --locked cargo-deny cargo-audit cargo-cyclonedx`).

## Aufbau

| Pfad | Inhalt |
|---|---|
| `src/` | Programm: Lesen des Exports, Prüfregeln, Berichte |
| `tests/` | Sicherheitstests, Prüffälle, Abgleich der Dokumentation |
| `tests/golden/` | 15 Prüffälle mit erwarteten Ausgaben in allen vier Formaten |
| `tests/fixtures/` | konstruierte Exporte mit bekannten Befunden |
| `start/` | Startdateien für Windows, macOS und Linux, Anleitung |
| `deny.toml` | erlaubte Lizenzen, verbotene Crates, erlaubte Herkunft |

## Externe Bibliotheken

Vier direkte Abhängigkeiten von crates.io (`serde_json`, `zip`, `sha2`, `sha1`), mit deren
Abhängigkeiten 23 Crates im Programm. Nur MIT-, Apache-2.0- und Zlib-Lizenzen, kein C-Code, keine
Netzwerk- oder TLS-Bibliotheken. Die CI prüft bei jeder Änderung und jeden Montag mit `cargo-deny`
und `cargo-audit` auf bekannte Schwachstellen. Vollständige Liste mit Version, Lizenz und Zweck:
[DOKUMENTATION.md, Abschnitt 13](DOKUMENTATION.md#13-externe-bibliotheken).

## Lizenz

Apache-2.0 – siehe [LICENSE](LICENSE) und [NOTICE](NOTICE).
