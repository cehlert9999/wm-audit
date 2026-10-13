#!/usr/bin/env bash
# Linux-Build (x86_64, statisch gelinkt gegen musl) in einem Docker-Container.
#
# Im Container laufen zuerst alle Tests (Golden-Files, Sicherheitseigenschaften),
# dann der Release-Build ohne lokale Pfade. Ergebnis:
#   dist/linux-x86_64/wm-audit   (+ .sha256)
#
# Auf Apple Silicon läuft der Container emuliert und braucht einige Minuten.
set -euo pipefail
cd "$(dirname "$0")"

ziel=dist/linux-x86_64
mkdir -p "$ziel"
# Prüffälle liegen im eigenständigen Repository unter tests/, im Entwicklungs-Repository
# daneben (../wm-audit/tests). Der Container sieht die Wurzel unter /src.
if [ -d tests/golden ]; then
    wurzel=$PWD; crate=/src; golden=/src/tests/golden
else
    wurzel=$PWD/..; crate=/src/wm-audit-rs; golden=/src/wm-audit/tests/golden
fi

docker run --rm --platform linux/amd64 \
    -v "$wurzel:/src" \
    -w "$crate" \
    -e CARGO_TARGET_DIR=/tmp/target \
    rust:alpine sh -euc '
        apk add --no-cache musl-dev >/dev/null
        echo "== Tests unter Linux"
        cargo test --release --locked
        echo "== Release-Build ohne lokale Pfade"
        export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo$(printf "\037")--remap-path-prefix='"$crate"'=/wm-audit-rs"
        cargo build --release --locked
        cp /tmp/target/release/wm-audit '"$ziel"'/wm-audit
        if grep -qE "'"$crate"'/src|/usr/local/cargo/registry" '"$ziel"'/wm-audit; then echo "FEHLER: lokaler Pfad im Binary" >&2; exit 1; fi
        if ldd '"$ziel"'/wm-audit 2>&1 | grep -q "=>"; then echo "FEHLER: nicht statisch gelinkt" >&2; exit 1; fi
        rustc --version
    '

(cd "$ziel" && shasum -a 256 wm-audit | tee wm-audit.sha256)
