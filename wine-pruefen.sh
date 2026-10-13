#!/bin/sh
# Prüffälle gegen wm-audit.exe unter Wine — läuft im Container von bauen-windows.sh.
#
#   sh wine-pruefen.sh <pfad/zu/wm-audit.exe>
#
# Arbeitsverzeichnis: der Ordner mit faelle.json und erwartet/. Braucht wine und jq.
# Jeder Fall wird in allen vier Formaten aufgerufen; Exit-Code und Ausgabe müssen
# Byte für Byte den erwarteten Dateien entsprechen.
set -eu
exe=$1
fehler=0
anzahl=$(jq length faelle.json)
i=0
while [ "$i" -lt "$anzahl" ]; do
    fall=$(jq -c ".[$i]" faelle.json)
    name=$(printf '%s' "$fall" | jq -r .name)
    pfad=$(printf '%s' "$fall" | jq -r .pfad)
    soll=$(printf '%s' "$fall" | jq -r '.exit // 0')
    nur_exit=$(printf '%s' "$fall" | jq -r '.nur_exit // false')
    # Die Argumente in faelle.json enthalten keine Leerzeichen.
    argumente=$(printf '%s' "$fall" | jq -r '(.argumente // []) | join(" ")')
    for endung in json txt html xml; do
        case $endung in
            json) schalter=--json ;;
            html) schalter=--html ;;
            xml) schalter=--junit ;;
            *) schalter= ;;
        esac
        set +e
        # shellcheck disable=SC2086 # Argumente und Schalter sollen aufgeteilt werden
        wine "$exe" "$pfad" $argumente $schalter >/tmp/ausgabe 2>/tmp/fehler
        code=$?
        set -e
        ok=1
        [ "$code" = "$soll" ] || ok=0
        if [ "$ok" = 1 ] && [ "$nur_exit" != true ]; then
            cmp -s /tmp/ausgabe "erwartet/$name.$endung" || ok=0
        fi
        if [ "$ok" = 0 ]; then
            fehler=$((fehler + 1))
            echo "ABWEICHUNG $name.$endung (Exit $code statt $soll)"
            tail -c 300 /tmp/fehler
        fi
    done
    i=$((i + 1))
done
if [ "$fehler" = 0 ]; then
    echo "Wine-Prüffälle: alle gleich"
else
    echo "Wine-Prüffälle: $fehler Abweichungen"
    exit 1
fi
