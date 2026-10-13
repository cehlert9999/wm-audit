#!/usr/bin/env bash
# Vollständige Prüfung für den Security-Review. Jeder Schritt muss grün sein.
#
#   ./pruefen.sh            braucht cargo-deny, cargo-audit, cargo-cyclonedx
set -euo pipefail
cd "$(dirname "$0")"

schritt() { printf '\n== %s\n' "$*"; }

schritt "Formatierung"
cargo fmt --check

schritt "Clippy (Warnungen sind Fehler; unwrap/expect/panic verboten)"
cargo clippy --all-targets --locked -- -D warnings

schritt "Tests (Golden-Files, Sicherheitseigenschaften, Einheiten)"
cargo test --locked

schritt "Lizenzen, Bann-Liste, Herkunft (cargo-deny)"
cargo deny check

schritt "Bekannte Schwachstellen (cargo-audit, RustSec)"
cargo audit

schritt "Keine Netzwerk-Crates im Abhängigkeitsbaum"
if cargo tree -e normal --prefix none | grep -Ei '^(reqwest|hyper|tokio|mio|socket2|curl|ureq|native-tls|openssl|rustls) '; then
    echo "FEHLER: Netzwerk-Crate gefunden" >&2
    exit 1
fi

schritt "SBOM (CycloneDX)"
cargo cyclonedx --format json --override-filename wm-audit.cdx >/dev/null
echo "wm-audit.cdx.json geschrieben"

schritt "Release-Build ohne lokale Pfade"
./bauen.sh

schritt "Alles grün"
