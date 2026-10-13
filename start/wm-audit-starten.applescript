-- wm-audit starten — ohne Terminal.
--
-- Doppelklick: Gateway-Export (ZIP oder Ordner) auswählen.
-- Oder: ZIP-Datei bzw. Ordner auf das App-Symbol ziehen.
-- Der Bericht (HTML mit Aufgabenliste) wird unter Dokumente/wm-audit Berichte/
-- gespeichert und im Standard-Browser geöffnet.
--
-- Bauen:  osacompile -o ~/Desktop/wm-audit.app wm-audit-starten.applescript

-- Das Programm liegt im Paket in der App (Contents/Resources/wm-audit);
-- sonst wird es in den üblichen Installationspfaden gesucht.
on wmAuditPfad()
	set kandidaten to {(POSIX path of (path to me)) & "Contents/Resources/wm-audit", "/opt/homebrew/bin/wm-audit", "/usr/local/bin/wm-audit"}
	repeat with kandidat in kandidaten
		try
			do shell script "test -x " & quoted form of (kandidat as text)
			return kandidat as text
		end try
	end repeat
	return ""
end wmAuditPfad

on run
	set wahl to button returned of (display dialog "Welchen webMethods-Gateway-Export möchten Sie prüfen?" & return & return & "Tipp: Sie können eine ZIP-Datei oder einen Ordner auch direkt auf das Symbol dieser App ziehen." buttons {"Abbrechen", "Ordner wählen", "ZIP-Datei wählen"} default button "ZIP-Datei wählen" cancel button "Abbrechen" with title "wm-audit" with icon note)
	if wahl is "ZIP-Datei wählen" then
		set ziel to choose file with prompt "Gateway-Export (ZIP) auswählen:" of type {"public.zip-archive"}
	else
		set ziel to choose folder with prompt "Entpackten Gateway-Export auswählen:"
	end if
	pruefen(ziel)
end run

on open eintraege
	repeat with eintrag in eintraege
		pruefen(eintrag)
	end repeat
end open

on pruefen(ziel)
	set wmAudit to wmAuditPfad()
	if wmAudit is "" then
		display dialog "wm-audit wurde nicht gefunden (weder in der App noch in /opt/homebrew/bin oder /usr/local/bin)." buttons {"OK"} default button "OK" with title "wm-audit" with icon stop
		return
	end if

	set pfad to POSIX path of ziel
	set exportName to do shell script "basename " & quoted form of pfad & " | sed -E 's/\\.[zZ][iI][pP]$//'"
	set zeit to do shell script "date +%Y-%m-%d_%H%M"
	set ordner to (POSIX path of (path to documents folder)) & "wm-audit Berichte/"
	do shell script "mkdir -p " & quoted form of ordner
	set bericht to ordner & "Bericht_" & exportName & "_" & zeit & ".html"

	try
		do shell script quoted form of wmAudit & " " & quoted form of pfad & " --html --output " & quoted form of bericht
	on error fehler
		display dialog "Der Export konnte nicht geprüft werden:" & return & return & fehler buttons {"OK"} default button "OK" with title "wm-audit" with icon stop
		return
	end try

	do shell script "open " & quoted form of bericht
end pruefen
