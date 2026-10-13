@echo off
rem wm-audit starten (Windows) - ohne Kommandozeile.
rem
rem   Gateway-Export (ZIP-Datei oder Ordner) auf diese Datei ziehen
rem   oder doppelklicken und eine ZIP-Datei auswaehlen.
rem
rem Der Bericht (HTML mit Aufgabenliste) wird unter Dokumente\wm-audit Berichte\
rem gespeichert und im Standard-Browser geoeffnet. wm-audit.exe muss im selben
rem Ordner liegen wie diese Datei.
setlocal EnableExtensions
chcp 65001 >nul

set "WM=%~dp0wm-audit.exe"
if not exist "%WM%" (
    echo wm-audit.exe nicht gefunden: "%WM%"
    pause
    exit /b 2
)

set "EXPORT=%~1"
set "PS_DIALOG=Add-Type -AssemblyName System.Windows.Forms; $d = New-Object System.Windows.Forms.OpenFileDialog; $d.Title = 'Gateway-Export (ZIP) auswaehlen'; $d.Filter = 'Gateway-Export (*.zip)|*.zip'; if ($d.ShowDialog() -eq 'OK') { $d.FileName }"
if "%EXPORT%"=="" for /f "usebackq delims=" %%f in (`powershell -NoProfile -STA -Command "%PS_DIALOG%"`) do set "EXPORT=%%f"
if "%EXPORT%"=="" exit /b 0

for /f "usebackq delims=" %%d in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('MyDocuments')"`) do set "DOKUMENTE=%%d"
for /f "usebackq delims=" %%t in (`powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd_HHmm"`) do set "ZEIT=%%t"
for %%i in ("%EXPORT%") do set "NAME=%%~ni"

set "ORDNER=%DOKUMENTE%\wm-audit Berichte"
if not exist "%ORDNER%" mkdir "%ORDNER%"
set "BERICHT=%ORDNER%\Bericht_%NAME%_%ZEIT%.html"

"%WM%" "%EXPORT%" --html --output "%BERICHT%"
if errorlevel 2 (
    echo.
    echo Der Export konnte nicht geprueft werden.
    pause
    exit /b 2
)
start "" "%BERICHT%"
endlocal
