#!/usr/bin/env bash
# Windows-Build (x86_64, wm-audit.exe) per Cross-Compiler in Docker, danach
# Golden-Test des .exe unter Wine 10 (Debian trixie; Wine 8 kennt ProcessPrng nicht).
#
#   dist/windows-x86_64/wm-audit.exe   (+ .sha256)
#
# Hinweis: Wine ersetzt keinen Test auf echtem Windows — die Startdatei
# wm-audit-starten.cmd läuft nur auf Windows selbst.
set -euo pipefail
cd "$(dirname "$0")"

ziel=dist/windows-x86_64
mkdir -p "$ziel"
# Prüffälle liegen im eigenständigen Repository unter tests/, im Entwicklungs-Repository
# daneben (../wm-audit/tests). Der Container sieht die Wurzel unter /src.
if [ -d tests/golden ]; then
    wurzel=$PWD; crate=/src; golden=/src/tests/golden
else
    wurzel=$PWD/..; crate=/src/wm-audit-rs; golden=/src/wm-audit/tests/golden
fi

# NUR_TEST=1 ./bauen-windows.sh prüft ein vorhandenes .exe, ohne neu zu bauen.
if [ "${NUR_TEST:-0}" != 1 ]; then
echo "== Cross-Build x86_64-pc-windows-gnu"
docker run --rm \
    -v "$wurzel:/src" \
    -w "$crate" \
    -e CARGO_TARGET_DIR=/tmp/target \
    rust:bookworm sh -euc '
        apt-get update -qq >/dev/null && apt-get install -y -qq gcc-mingw-w64-x86-64 >/dev/null
        rustup target add x86_64-pc-windows-gnu >/dev/null
        export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo$(printf "\037")--remap-path-prefix='"$crate"'=/wm-audit-rs"
        cargo build --release --locked --target x86_64-pc-windows-gnu
        cp /tmp/target/x86_64-pc-windows-gnu/release/wm-audit.exe '"$ziel"'/wm-audit.exe
        if grep -qE "'"$crate"'/src|/usr/local/cargo/registry" '"$ziel"'/wm-audit.exe; then echo "FEHLER: lokaler Pfad im Binary" >&2; exit 1; fi
    '
fi

echo "== Golden-Test unter Wine"
docker run --rm --platform linux/amd64 \
    -v "$wurzel:/src" \
    -w "$golden" \
    debian:trixie sh -euc '
        apt-get update -qq >/dev/null && apt-get install -y -qq wine wine64 jq >/dev/null
        export WINEDEBUG=-all WINEPREFIX=/tmp/wine
        sh '"$crate"'/wine-pruefen.sh '"$crate"'/'"$ziel"'/wm-audit.exe
    '

(cd "$ziel" && shasum -a 256 wm-audit.exe | tee wm-audit.exe.sha256)
