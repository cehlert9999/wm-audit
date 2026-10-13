# wm-audit — Kurzanleitung

wm-audit prüft den Export eines **webMethods API Gateway** (ZIP-Datei oder entpackter
Ordner) und erstellt einen Bericht mit Aufgabenliste. Es läuft lokal, ohne Netzwerk
und ohne Installation, und öffnet die Zugangsdaten im Export nicht.

## Inhalt

| Ordner / Datei | Inhalt |
|---|---|
| `windows-x86_64/` | `wm-audit.exe` und die Startdatei `wm-audit-starten.cmd` |
| `macos/` | `wm-audit.app` (Programm eingebaut) und `wm-audit` (Kommandozeile, Apple Silicon und Intel) |
| `linux-x86_64/` | `wm-audit` (statisch gelinkt, ohne Abhängigkeiten) und `wm-audit-starten.sh` |
| `SICHERHEIT.md` | Sicherheitsdatenblatt: jede Zusage mit Testnachweis |
| `Datenblatt_wm-audit.pdf` | Produktdatenblatt |
| `wm-audit.cdx.json` | Stückliste der Abhängigkeiten (SBOM, CycloneDX) |
| `quelltext.tar.gz` | Quelltext dieses Stands inklusive Testfälle |
| `SHA256SUMS` | Prüfsummen aller Dateien |

## 1. Prüfsummen kontrollieren

```sh
shasum -a 256 -c SHA256SUMS                            # macOS / Linux
Get-FileHash .\windows-x86_64\wm-audit.exe -Algorithm SHA256   # Windows (PowerShell)
```

## 2. Starten

**Windows:** Den Export auf `wm-audit-starten.cmd` ziehen – oder doppelklicken und eine
ZIP-Datei auswählen. Der Bericht öffnet sich im Browser. Die Dateien sind nicht signiert;
meldet Windows SmartScreen „Der Computer wurde durch Windows geschützt“, über
„Weitere Informationen“ → „Trotzdem ausführen“ starten.

**macOS:** Den Export auf `wm-audit.app` ziehen – oder doppelklicken. Die App ist nicht
notarisiert: beim ersten Start mit Rechtsklick → „Öffnen“ starten. Ab macOS 15 erscheint
dieser Weg nicht mehr; dann unter Systemeinstellungen → Datenschutz & Sicherheit die App
freigeben („Dennoch öffnen“).

**Linux:** `./wm-audit-starten.sh export.zip` – mit grafischer Oberfläche und installiertem
`zenity` auch ohne Argument mit Dateiauswahl.

Die Berichte landen jeweils unter **Dokumente/wm-audit Berichte/**.

**Kommandozeile (alle Plattformen):**

```sh
wm-audit export.zip --html --output bericht.html   # Bericht mit Aufgabenliste
wm-audit export.zip                                # Text
wm-audit export.zip --json                         # JSON für Pipelines
wm-audit export.zip --junit -o junit.xml --fail-on high  # JUnit-XML für Jenkins, GitLab …
wm-audit export.zip --fail-on high                 # Exit 1 bei belegtem Befund ab "high"
```

Exit-Codes: `0` geprüft · `1` `--fail-on` ausgelöst · `2` Aufruf- oder Lesefehler.
Vollständige Beschreibung aller Optionen und Formate: DOKUMENTATION.md bzw. https://leanofy.de/wm-audit/dokumentation

## 3. Den Bericht lesen

Oben stehen **Ihre Aufgaben**: was sofort zu beheben ist und was zu prüfen ist. Zu jeder
Aufgabe gibt es weiter unten die Klickschritte im API Gateway, einen Test für den Erfolg
und einen Link zur IBM-Dokumentation.

## 4. Für das Security-Review

- `SICHERHEIT.md` nennt zu jeder Zusage die Umsetzung und den Test, der sie belegt.
- `quelltext.tar.gz` enthält genau den Stand dieses Pakets. Darin führt
  `code/wm-audit-rs/pruefen.sh` alle Prüfungen in einem Lauf aus: Tests, statische Analyse,
  Lizenz- und Schwachstellenprüfung, SBOM, reproduzierbarer Build.
  Unter macOS meldet `tar` beim Entpacken „Failed to restore metadata“ für `._API.r2`:
  eine absichtliche Testdatei (macOS-Zusatzdatei, wie sie in echten Exporten vorkommt).
  macOS legt sie nicht als Datei ab; die Ergebnisse der Tests ändern sich dadurch nicht.
- Die Programme sind **nicht** mit einem Hersteller-Zertifikat signiert (Apple Developer ID
  bzw. Windows Authenticode).
