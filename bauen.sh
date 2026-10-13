#!/usr/bin/env bash
# Release-Build ohne lokale Pfade im Binary.
#
# Ohne Umschreiben stünden Build-Pfade wie /Users/<name>/.cargo/registry/…
# im Binary (Panic-Ortsangaben der Abhängigkeiten). Sie verraten Benutzernamen
# und machen den Build von der Maschine abhängig.
set -euo pipefail
cd "$(dirname "$0")"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"
# CARGO_ENCODED_RUSTFLAGS trennt mit 0x1f — Pfade mit Leerzeichen bleiben heil.
trenner=$'\x1f'
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${cargo_home}=/cargo${trenner}--remap-path-prefix=${PWD}=/wm-audit-rs"

cargo build --release --locked

binary=target/release/wm-audit
if strings "$binary" | grep -q "$HOME"; then
    echo "FEHLER: lokaler Pfad im Binary" >&2
    exit 1
fi
shasum -a 256 "$binary"
