//! DOKUMENTATION.md beschreibt genau dieses Programm: die Ausgabe von `--help`
//! steht wörtlich darin, und die Versionsnummer stimmt. Wer die Kommandozeile
//! ändert, muss die Dokumentation mitziehen — sonst schlägt dieser Test fehl.

#![allow(clippy::unwrap_used)]

use std::process::Command;

const DOKU: &str = include_str!("../DOKUMENTATION.md");

#[test]
fn hilfe_steht_woertlich_in_der_dokumentation() {
    let lauf = Command::new(env!("CARGO_BIN_EXE_wm-audit"))
        .arg("--help")
        .output()
        .unwrap();
    let hilfe = String::from_utf8(lauf.stdout).unwrap();
    assert!(
        DOKU.contains(hilfe.trim_end()),
        "DOKUMENTATION.md: Abschnitt „Ausgabe von wm-audit --help“ ist veraltet"
    );
}

#[test]
fn version_der_dokumentation_stimmt() {
    let version = env!("CARGO_PKG_VERSION");
    assert!(DOKU.contains(&format!("Version {version}")));
    assert!(DOKU.contains(&format!("`wm-audit {version}`")));
}

/// Jedes Paket aus `Cargo.lock` steht mit seiner Version im Abschnitt
/// „Externe Bibliotheken“ — eine neue oder aktualisierte Abhängigkeit fällt auf.
#[test]
fn externe_bibliotheken_vollstaendig_dokumentiert() {
    let lock = include_str!("../Cargo.lock");
    let mut name = None;
    let mut fehlend = Vec::new();
    for zeile in lock.lines() {
        if let Some(n) = zeile.strip_prefix("name = ") {
            name = Some(n.trim_matches('"'));
        } else if let (Some(n), Some(v)) = (name, zeile.strip_prefix("version = ")) {
            let v = v.trim_matches('"');
            if n != "wm-audit" && !DOKU.contains(&format!("| `{n}` | {v} |")) {
                fehlend.push(format!("{n} {v}"));
            }
            name = None;
        }
    }
    assert!(
        fehlend.is_empty(),
        "DOKUMENTATION.md, Abschnitt „Externe Bibliotheken“: fehlt {fehlend:?}"
    );
}
