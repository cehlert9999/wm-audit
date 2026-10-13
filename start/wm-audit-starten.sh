#!/bin/sh
# wm-audit starten (Linux).
#
#   ./wm-audit-starten.sh <export.zip | export-ordner>
#
# Ohne Argument öffnet sich eine Dateiauswahl, falls zenity installiert ist.
# Der Bericht (HTML mit Aufgabenliste) wird unter <Dokumente>/wm-audit Berichte/
# gespeichert und, wenn eine grafische Oberfläche läuft, im Browser geöffnet.
# wm-audit muss im selben Ordner liegen wie dieses Skript.
set -eu

hier=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
wm="$hier/wm-audit"
[ -x "$wm" ] || { echo "wm-audit nicht gefunden: $wm" >&2; exit 2; }

export_pfad=${1:-}
if [ -z "$export_pfad" ] && command -v zenity >/dev/null 2>&1; then
    export_pfad=$(zenity --file-selection --title="Gateway-Export (ZIP) auswählen" --file-filter="*.zip") || exit 0
fi
[ -n "$export_pfad" ] || { echo "Aufruf: $0 <export.zip | export-ordner>" >&2; exit 2; }

dokumente=$(xdg-user-dir DOCUMENTS 2>/dev/null || echo "$HOME")
ordner="$dokumente/wm-audit Berichte"
mkdir -p "$ordner"
name=$(basename -- "$export_pfad")
name=${name%.zip}
name=${name%.ZIP}
bericht="$ordner/Bericht_${name}_$(date +%Y-%m-%d_%H%M).html"

"$wm" "$export_pfad" --html --output "$bericht"
echo "Bericht: $bericht"
if command -v xdg-open >/dev/null 2>&1 && [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then
    xdg-open "$bericht" >/dev/null 2>&1 &
fi
