//! Kommandozeile: `wm-audit EXPORT [--json | --html | --junit] [--output DATEI] [--fail-on SCHWERE]`.
//!
//! Exit-Codes: 0 = gelesen, 1 = `--fail-on` ausgelöst, 2 = Aufruf- oder Lesefehler.
//! Dieselbe Schnittstelle wie die Referenzimplementierung.

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use wm_audit::befund::Severity;
use wm_audit::bericht::{
    als_html, als_json, als_junit, als_text, bericht, ueber_schwelle, werkzeug,
};
use wm_audit::lesen::{Grenzen, read_export};

const HILFE: &str = "\
usage: wm-audit [-h] [--json | --html | --junit] [--output OUTPUT] [--fail-on {critical,high,medium,low,info}] [--version] export

Statische Security-Analyse eines webMethods-API-Gateway-Exports.

positional arguments:
  export                Export als ZIP-Datei oder entpacktes Verzeichnis

options:
  -h, --help            Hilfe anzeigen und beenden
  --json                Bericht als JSON ausgeben
  --html                Bericht als HTML-Datei mit Aufgabenliste (für Menschen)
  --junit               Bericht als JUnit-XML für CI-Systeme (Jenkins, GitLab …)
  --output, -o OUTPUT   Bericht in diese Datei schreiben statt auf stdout
  --fail-on {critical,high,medium,low,info}
                        Exit-Code 1, wenn ein belegter Befund mindestens diese Schwere hat
  --version             Version anzeigen und beenden
";

#[derive(Debug, Default)]
struct Aufruf {
    export: Option<PathBuf>,
    json: bool,
    html: bool,
    junit: bool,
    ausgabe: Option<PathBuf>,
    fail_on: Option<Severity>,
}

enum Weiter {
    Laufen(Aufruf),
    Fertig(u8),
}

fn schwere(wert: Option<OsString>) -> Result<Severity, String> {
    let wert = wert.ok_or("--fail-on braucht einen Wert")?;
    let text = wert.to_str().unwrap_or_default();
    Severity::aus_code(text).ok_or_else(|| format!("--fail-on: ungültige Schwere {text:?}"))
}

fn argumente(args: Vec<OsString>) -> Result<Weiter, String> {
    let mut aufruf = Aufruf::default();
    let mut args = args.into_iter();
    let mut nur_positionen = false;
    while let Some(arg) = args.next() {
        let text = arg.to_str().map(str::to_owned);
        match text.as_deref() {
            Some(t) if !nur_positionen && t.starts_with('-') && t != "-" => match t {
                "--" => nur_positionen = true,
                "-h" | "--help" => {
                    print!("{HILFE}");
                    return Ok(Weiter::Fertig(0));
                }
                "--version" => {
                    println!("{}", werkzeug());
                    return Ok(Weiter::Fertig(0));
                }
                "--json" => aufruf.json = true,
                "--html" => aufruf.html = true,
                "--junit" => aufruf.junit = true,
                "--output" | "-o" => {
                    aufruf.ausgabe = Some(args.next().ok_or("--output braucht einen Wert")?.into());
                }
                "--fail-on" => aufruf.fail_on = Some(schwere(args.next())?),
                _ => {
                    if let Some(wert) = t.strip_prefix("--output=") {
                        aufruf.ausgabe = Some(wert.into());
                    } else if let Some(wert) = t.strip_prefix("--fail-on=") {
                        aufruf.fail_on = Some(schwere(Some(wert.into()))?);
                    } else {
                        return Err(format!("unbekannte Option: {t}"));
                    }
                }
            },
            _ => {
                if aufruf.export.is_some() {
                    return Err("nur ein Export je Aufruf".to_owned());
                }
                aufruf.export = Some(arg.into());
            }
        }
    }
    if [aufruf.json, aufruf.html, aufruf.junit]
        .iter()
        .filter(|x| **x)
        .count()
        > 1
    {
        return Err("--json, --html und --junit schließen sich gegenseitig aus".to_owned());
    }
    Ok(Weiter::Laufen(aufruf))
}

fn ausfuehren(aufruf: Aufruf) -> Result<u8, String> {
    let export_pfad = aufruf.export.ok_or("Export fehlt")?;
    let export = read_export(&export_pfad, &Grenzen::STANDARD).map_err(|e| e.to_string())?;
    let b = bericht(&export);
    let ausgabe = if aufruf.json {
        als_json(&b)
    } else if aufruf.html {
        als_html(&b)
    } else if aufruf.junit {
        als_junit(&b, aufruf.fail_on)
    } else {
        als_text(&b)
    };
    match &aufruf.ausgabe {
        Some(ziel) => {
            std::fs::write(ziel, ausgabe.as_bytes())
                .map_err(|e| format!("{}: {e}", ziel.display()))?;
        }
        None => {
            let mut stdout = std::io::stdout().lock();
            stdout
                .write_all(ausgabe.as_bytes())
                .and_then(|()| stdout.flush())
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(match aufruf.fail_on {
        Some(schwelle) if ueber_schwelle(&b, schwelle) => 1,
        _ => 0,
    })
}

fn main() -> ExitCode {
    let aufruf = match argumente(std::env::args_os().skip(1).collect()) {
        Ok(Weiter::Laufen(aufruf)) => aufruf,
        Ok(Weiter::Fertig(code)) => return ExitCode::from(code),
        Err(meldung) => {
            eprint!("{HILFE}");
            eprintln!("wm-audit: error: {meldung}");
            return ExitCode::from(2);
        }
    };
    match ausfuehren(aufruf) {
        Ok(code) => ExitCode::from(code),
        Err(meldung) => {
            eprintln!("wm-audit: {meldung}");
            ExitCode::from(2)
        }
    }
}
