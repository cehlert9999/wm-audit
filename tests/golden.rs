//! Golden-Files: das Binary liefert für jeden Fall exakt die Ausgabe der
//! Referenzimplementierung (Prüffälle unter `tests/golden`), Byte für Byte, und endet mit
//! demselben Exit-Code.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Prüffälle: im eigenständigen Repository unter `tests/`, im
/// Entwicklungs-Repository bei der Referenz (`../wm-audit/tests/`).
fn pruefdaten(name: &str) -> PathBuf {
    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let eigen = crate_dir.join("tests").join(name);
    if eigen.is_dir() {
        eigen
    } else {
        crate_dir.join("../wm-audit/tests").join(name)
    }
}

fn golden() -> PathBuf {
    pruefdaten("golden")
}

#[test]
fn ausgaben_entsprechen_den_pruefaellen() {
    let manifest: Value =
        serde_json::from_str(&std::fs::read_to_string(golden().join("faelle.json")).unwrap())
            .unwrap();
    let faelle = manifest.as_array().unwrap();
    assert!(faelle.len() >= 10, "Manifest unvollständig");

    let mut abweichungen = Vec::new();
    for fall in faelle {
        let name = fall["name"].as_str().unwrap();
        let pfad = golden().join(fall["pfad"].as_str().unwrap());
        let argumente: Vec<&str> = fall
            .get("argumente")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default();
        let exit = fall.get("exit").and_then(Value::as_i64).unwrap_or(0);
        let nur_exit = fall
            .get("nur_exit")
            .and_then(Value::as_bool)
            .unwrap_or(false);

        for (endung, schalter) in [
            ("json", Some("--json")),
            ("txt", None),
            ("html", Some("--html")),
            ("xml", Some("--junit")),
        ] {
            let mut befehl = Command::new(env!("CARGO_BIN_EXE_wm-audit"));
            befehl.arg(&pfad).args(&argumente);
            if let Some(s) = schalter {
                befehl.arg(s);
            }
            let lauf = befehl.output().unwrap();
            let code = i64::from(lauf.status.code().unwrap_or(-1));
            if code != exit {
                abweichungen.push(format!("{name}.{endung}: Exit {code} statt {exit}"));
                continue;
            }
            if nur_exit {
                continue;
            }
            let soll =
                std::fs::read(golden().join("erwartet").join(format!("{name}.{endung}"))).unwrap();
            if lauf.stdout != soll {
                abweichungen.push(format!("{name}.{endung}: Ausgabe weicht ab"));
            }
        }
    }
    assert!(abweichungen.is_empty(), "{abweichungen:#?}");
}
