//! Sicherheitseigenschaften, die im Security-Review zugesagt werden.
//!
//! Jeder Test hier entspricht einem Punkt in `SICHERHEIT.md`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use wm_audit::bericht::{als_json, bericht};
use wm_audit::lesen::{Grenzen, read_directory, read_export, read_zip};

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

fn fixtures() -> PathBuf {
    pruefdaten("fixtures")
}

/// Frisches Arbeitsverzeichnis unter `target/tmp`.
fn arbeitsordner(name: &str) -> PathBuf {
    let ordner = Path::new(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = fs::remove_dir_all(&ordner);
    fs::create_dir_all(&ordner).unwrap();
    ordner
}

fn mini_export(wurzel: &Path, api_name: &str) {
    let ordner = wurzel.join("API/API.m");
    fs::create_dir_all(&ordner).unwrap();
    fs::write(
        ordner.join("API.m"),
        format!(r#"{{"apiName": "{api_name}"}}"#),
    )
    .unwrap();
}

fn gruende(export: &wm_audit::modell::GatewayExport) -> Vec<&'static str> {
    export
        .uebersprungen
        .iter()
        .map(|u| u.grund.code())
        .collect()
}

// ------------------------------------------------------------ Zugangsdaten

#[test]
fn gesperrte_assets_werden_nie_geoeffnet() {
    // Die Fixtures enthalten Kanarienvögel unter PassmanData und Truststore.
    // Würden sie gelesen, stünde "GEHEIM-KANARIE" im Bericht.
    for (pfad, gesperrt) in [
        (fixtures(), 2),
        (golden().join("faelle/fixtures.zip"), 2),
        (golden().join("faelle/robust"), 4),
        (golden().join("faelle/robust.zip"), 5),
    ] {
        let export = read_export(&pfad, &Grenzen::STANDARD).unwrap();
        assert_eq!(export.gesperrt, gesperrt, "{}", pfad.display());
        let text = als_json(&bericht(&export));
        assert!(!text.contains("GEHEIM"), "{}", pfad.display());
    }
}

#[test]
fn zugangsdaten_in_urls_werden_geschwaerzt() {
    let text = als_json(&bericht(
        &read_export(&fixtures(), &Grenzen::STANDARD).unwrap(),
    ));
    assert!(!text.contains("svc-user"));
    assert!(text.contains("http://***@backend.intern:8080"));
}

// ------------------------------------------------------------ Dateisystem

#[cfg(unix)]
#[test]
fn symlinks_werden_nicht_verfolgt() {
    let ordner = arbeitsordner("symlink");
    let draussen = ordner.join("draussen");
    fs::create_dir_all(&draussen).unwrap();
    fs::write(draussen.join("API.s"), r#"{"apiName": "GEHEIM-KANARIE"}"#).unwrap();
    let export = ordner.join("export");
    mini_export(&export, "Mini");
    fs::create_dir_all(export.join("API/API.s")).unwrap();
    std::os::unix::fs::symlink(draussen.join("API.s"), export.join("API/API.s/API.s")).unwrap();
    std::os::unix::fs::symlink(&draussen, export.join("API/API.ordner")).unwrap();

    let e = read_directory(&export, &Grenzen::STANDARD).unwrap();
    assert_eq!(
        e.apis.iter().map(|a| a.name.as_str()).collect::<Vec<_>>(),
        ["Mini"]
    );
    assert_eq!(gruende(&e), ["symlink"]);
    assert!(!als_json(&bericht(&e)).contains("GEHEIM"));
}

#[cfg(unix)]
#[test]
fn fifo_wird_nicht_geoeffnet() {
    let ordner = arbeitsordner("fifo");
    mini_export(&ordner, "Mini");
    fs::create_dir_all(ordner.join("API/API.f")).unwrap();
    let ok = Command::new("mkfifo")
        .arg(ordner.join("API/API.f/API.f"))
        .status();
    if !ok.is_ok_and(|s| s.success()) {
        return; // ohne mkfifo nicht prüfbar
    }
    let e = read_directory(&ordner, &Grenzen::STANDARD).unwrap();
    assert_eq!(e.apis.len(), 1);
}

fn zustand(wurzel: &Path) -> BTreeMap<PathBuf, (u64, Option<SystemTime>)> {
    let mut stand = BTreeMap::new();
    let mut offen = vec![wurzel.to_path_buf()];
    while let Some(ordner) = offen.pop() {
        for e in fs::read_dir(&ordner).unwrap().flatten() {
            let info = fs::symlink_metadata(e.path()).unwrap();
            if info.is_dir() {
                offen.push(e.path());
            }
            stand.insert(e.path(), (info.len(), info.modified().ok()));
        }
    }
    stand
}

#[test]
fn export_wird_nicht_veraendert() {
    let vorher = zustand(&fixtures());
    let lauf = Command::new(env!("CARGO_BIN_EXE_wm-audit"))
        .arg(fixtures())
        .arg("--json")
        .output()
        .unwrap();
    assert!(lauf.status.success());
    assert_eq!(zustand(&fixtures()), vorher);
}

#[test]
fn geschrieben_wird_nur_die_ausgabedatei() {
    let ordner = arbeitsordner("ausgabe");
    let ziel = ordner.join("bericht.json");
    let lauf = Command::new(env!("CARGO_BIN_EXE_wm-audit"))
        .arg(fixtures())
        .args(["--json", "--output"])
        .arg(&ziel)
        .output()
        .unwrap();
    assert!(lauf.status.success());
    assert!(lauf.stdout.is_empty());
    assert_eq!(fs::read_dir(&ordner).unwrap().count(), 1);
    assert!(
        fs::read_to_string(&ziel)
            .unwrap()
            .contains("wm-audit-bericht/1")
    );
}

// ------------------------------------------------------------ Grenzen

#[test]
fn grenze_je_datei() {
    let ordner = arbeitsordner("grenze-datei");
    mini_export(&ordner, &"x".repeat(200));
    let e = read_directory(
        &ordner,
        &Grenzen {
            datei: 100,
            ..Grenzen::STANDARD
        },
    )
    .unwrap();
    assert_eq!(gruende(&e), ["zu_gross"]);
}

#[test]
fn grenze_gesamt_bricht_ab() {
    assert!(
        read_export(
            &fixtures(),
            &Grenzen {
                gesamt: 1000,
                ..Grenzen::STANDARD
            }
        )
        .is_err()
    );
}

#[test]
fn grenze_eintraege_bricht_ab() {
    let grenzen = Grenzen {
        eintraege: 3,
        ..Grenzen::STANDARD
    };
    assert!(read_export(&fixtures(), &grenzen).is_err());
    assert!(read_export(&golden().join("faelle/fixtures.zip"), &grenzen).is_err());
}

#[test]
fn grenze_tiefe() {
    let ordner = arbeitsordner("grenze-tiefe");
    fs::create_dir_all(ordner.join("API/API.t")).unwrap();
    fs::write(
        ordner.join("API/API.t/API.t"),
        r#"{"apiName": "T", "x": [[[]]]}"#,
    )
    .unwrap();
    let flach = read_directory(
        &ordner,
        &Grenzen {
            tiefe: 3,
            ..Grenzen::STANDARD
        },
    )
    .unwrap();
    assert_eq!(gruende(&flach), ["zu_tief"]);
    let tief = read_directory(
        &ordner,
        &Grenzen {
            tiefe: 4,
            ..Grenzen::STANDARD
        },
    )
    .unwrap();
    assert_eq!(tief.apis[0].name, "T");
}

#[test]
fn json_tiefenbombe_ueberlaeuft_keinen_stapel() {
    let ordner = arbeitsordner("tiefenbombe");
    fs::create_dir_all(ordner.join("API/API.t")).unwrap();
    let bombe = format!("{}{}", "[".repeat(1_000_000), "]".repeat(1_000_000));
    fs::write(ordner.join("API/API.t/API.t"), bombe).unwrap();
    let e = read_directory(&ordner, &Grenzen::STANDARD).unwrap();
    assert_eq!(gruende(&e), ["zu_tief"]);
}

#[test]
fn zip_bombe_wird_nicht_ausgepackt() {
    // 256 MiB Nullen komprimieren auf rund 250 KB — gelesen wird höchstens die Grenze.
    let ordner = arbeitsordner("zip-bombe");
    let pfad = ordner.join("bombe.zip");
    let mut zip = zip::ZipWriter::new(fs::File::create(&pfad).unwrap());
    let optionen = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .large_file(true);
    zip.start_file("API/API.b/API.b", optionen).unwrap();
    let block = vec![0u8; 1 << 20];
    for _ in 0..256 {
        zip.write_all(&block).unwrap();
    }
    zip.finish().unwrap();

    let e = read_zip(
        &pfad,
        &Grenzen {
            datei: 1 << 20,
            ..Grenzen::STANDARD
        },
    )
    .unwrap();
    assert_eq!(gruende(&e), ["zu_gross"]);
}

#[test]
fn doppelte_eintragsnamen_werden_abgelehnt() {
    assert!(read_zip(&golden().join("faelle/doppelt.zip"), &Grenzen::STANDARD).is_err());
}

// ------------------------------------------------------------ Quelltext

/// Kein Netzwerk, keine Prozesse, kein `unsafe` — geprüft am Quelltext.
/// (`unsafe` ist zusätzlich per `forbid`-Lint in `Cargo.toml` verboten.)
#[test]
fn quelltext_ohne_netzwerk_prozesse_und_unsafe() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for eintrag in fs::read_dir(src).unwrap().flatten() {
        let text = fs::read_to_string(eintrag.path()).unwrap();
        for verboten in [
            "std::net",
            "TcpStream",
            "UdpSocket",
            "std::process::Command",
            "unsafe ",
        ] {
            assert!(
                !text.contains(verboten),
                "{verboten} in {}",
                eintrag.path().display()
            );
        }
    }
}

// ------------------------------------------------------------ HTML-Bericht

/// Ein API-Name mit Skript-Tags darf den JSON-Datenblock nicht verlassen.
#[test]
fn html_bericht_laesst_keinen_code_aus_dem_export_durch() {
    let ordner = arbeitsordner("html-xss");
    mini_export(&ordner, "</script><script>alert(1)</script><!--");
    let html = wm_audit::bericht::als_html(&bericht(
        &read_directory(&ordner, &Grenzen::STANDARD).unwrap(),
    ));
    let vorlage = include_str!("../src/bericht.html");
    assert_eq!(
        html.matches("</script>").count(),
        vorlage.matches("</script>").count()
    );
    assert!(!html.contains("<script>alert"));
    assert!(html.contains("\\u003c/script>\\u003cscript>alert(1)"));
}

/// Die HTML-Vorlage lädt nichts nach und setzt nichts als HTML ein.
#[test]
fn html_vorlage_laedt_nichts_nach() {
    let vorlage = include_str!("../src/bericht.html");
    assert!(vorlage.contains("default-src 'none'"));
    for verboten in [
        ".innerHTML",
        "insertAdjacentHTML",
        "fetch(",
        "XMLHttpRequest",
        "import(",
    ] {
        assert!(!vorlage.contains(verboten), "{verboten}");
    }
}

/// Die Vorlage ist identisch mit der Referenzimplementierung.
///
/// Die Referenz liegt nur im Entwicklungs-Repository; im öffentlichen Repository
/// stehen neben dieser Crate nur ihre Prüffälle. Fehlt das Referenzpaket
/// (`pyproject.toml`), gibt es nichts zu vergleichen — ist es da, muss auch die
/// Vorlage da und gleich sein.
#[test]
fn html_vorlage_gleich_referenz() {
    let referenz = Path::new(env!("CARGO_MANIFEST_DIR")).join("../wm-audit");
    if !referenz.join("pyproject.toml").is_file() {
        return;
    }
    assert_eq!(
        fs::read_to_string(referenz.join("src/wm_audit/bericht.html")).unwrap(),
        include_str!("../src/bericht.html")
    );
}
