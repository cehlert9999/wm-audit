//! Einlesen eines webMethods-API-Gateway-Exports.
//!
//! ZIP und Verzeichnis laufen durch dieselbe Logik ([`Aufbau`]); sie
//! unterscheiden sich nur darin, woher die Bytes kommen.
//!
//! Erkannt werden die Assets am Namen:
//!
//! * **API-Datei** — `API.<x>` in einem Verzeichnis, das ebenfalls `API.<x>` heißt;
//! * **Policy** — `Policy.<x>` in `Policy.<x>` unterhalb einer API;
//! * **Policy-Aktion** — `PolicyAction.<x>` unterhalb eines `API.*`-Verzeichnisses;
//! * **Alias** — `Alias.<x>` in einem Verzeichnis `Alias`.
//!
//! Jede API ist über ihren Verzeichnispfad eindeutig, nicht über ihre UUID —
//! eine Policy aus `prod/` verdeckt nie eine Lücke in `test/`.
//!
//! **Gesperrte Einträge** (`PassmanData`, `Keystore`, `Truststore`, `Kerberos`
//! als Pfadteil oder Präfix `<Name>.`) werden nie geöffnet, nie dekomprimiert,
//! nur gezählt.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};
use zip::{CompressionMethod, ZipArchive};

use crate::modell::{
    GatewayApi, GatewayExport, Grund, NativeEndpoint, PolicyAction, Uebersprungen,
};
use crate::werte::{self, Objekt};

/// Assets, die niemals geöffnet werden — sie enthalten Geheimnisse.
pub const GESPERRTE_ASSETS: [&str; 4] = ["PassmanData", "Keystore", "Truststore", "Kerberos"];

/// Obergrenzen gegen ZIP- und JSON-Bomben.
#[derive(Debug, Clone, Copy)]
pub struct Grenzen {
    /// Einträge im ZIP-Verzeichnis bzw. reguläre Dateien im Verzeichnisbaum.
    pub eintraege: usize,
    /// Bytes je Asset-Datei (nach dem Entpacken).
    pub datei: u64,
    /// Gelesene Bytes über alle Asset-Dateien zusammen.
    pub gesamt: u64,
    /// Verschachtelungstiefe von JSON-Arrays/-Objekten.
    pub tiefe: usize,
}

impl Grenzen {
    pub const STANDARD: Grenzen = Grenzen {
        eintraege: 50_000,
        datei: 32 * 1024 * 1024,
        gesamt: 512 * 1024 * 1024,
        tiefe: 100,
    };
}

impl Default for Grenzen {
    fn default() -> Self {
        Self::STANDARD
    }
}

/// Der Export ist als Ganzes nicht lesbar.
#[derive(Debug)]
pub struct ExportFehler(pub String);

impl fmt::Display for ExportFehler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ExportFehler {}

// ------------------------------------------------------------------ Pfade

fn teile(name: &str) -> Vec<String> {
    name.replace('\\', "/")
        .split('/')
        .filter(|t| !t.is_empty() && *t != ".")
        .map(str::to_owned)
        .collect()
}

/// Ist ein Pfadteil gesperrt (Name oder Präfix `<Name>.`, ohne Groß-/Kleinschreibung)?
pub fn ist_gesperrt<S: AsRef<str>>(teile: &[S]) -> bool {
    teile.iter().any(|t| {
        let k = t.as_ref().to_lowercase();
        GESPERRTE_ASSETS.iter().any(|s| {
            let s = s.to_lowercase();
            k == s || k.starts_with(&format!("{s}."))
        })
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Art {
    Api,
    Policy,
    Aktion,
    Alias,
}

fn innerste_api(teile: &[String]) -> Option<String> {
    let eltern = teile.get(..teile.len().checked_sub(1)?)?;
    let i = eltern.iter().rposition(|t| t.starts_with("API."))?;
    Some(eltern.get(..=i)?.join("/"))
}

/// API-Datei, Policy, Policy-Aktion, Alias oder uninteressant.
fn einordnen(teile: &[String]) -> Option<(Art, String)> {
    let [vorne @ .., eltern, name] = teile else {
        return None;
    };
    if name.starts_with("API.") && name == eltern {
        let mut pfad: Vec<&str> = vorne.iter().map(String::as_str).collect();
        pfad.push(eltern);
        return Some((Art::Api, pfad.join("/")));
    }
    if name.starts_with("Policy.") && name == eltern {
        return innerste_api(teile).map(|k| (Art::Policy, k));
    }
    if name.starts_with("PolicyAction.") {
        return innerste_api(teile).map(|k| (Art::Aktion, k));
    }
    if name.starts_with("Alias.") && eltern == "Alias" {
        return Some((Art::Alias, vorne.join("/")));
    }
    None
}

// ------------------------------------------------------------------ Aufbau

fn dekodieren(daten: &[u8], grenzen: &Grenzen) -> Result<Objekt, Grund> {
    let quelle = std::str::from_utf8(daten).map_err(|_| Grund::KeinUtf8)?;
    if werte::verschachtelung(quelle) > grenzen.tiefe {
        return Err(Grund::ZuTief);
    }
    match werte::lade_json(quelle) {
        Some(Value::Object(o)) => Ok(o),
        Some(_) => Err(Grund::KeinObjekt),
        None => Err(Grund::KeinJson),
    }
}

/// IDs aller Aktionen in `policyEnforcements`; `None`, wenn das Feld keine Liste ist.
fn zugeordnete_ids(raw: &Objekt) -> Option<HashSet<String>> {
    let stages = raw.get("policyEnforcements").filter(|v| v.is_array())?;
    Some(
        werte::objekte(Some(stages))
            .into_iter()
            .flat_map(|stage| werte::objekte(stage.get("enforcements")))
            .map(|e| werte::text(e.get("enforcementObjectId")))
            .collect(),
    )
}

fn native_endpoints(raw: Option<&Value>) -> Vec<NativeEndpoint> {
    let eintraege: Vec<&Value> = match raw {
        Some(Value::Array(a)) => a.iter().collect(),
        Some(o @ Value::Object(_)) => vec![o],
        _ => Vec::new(),
    };
    eintraege
        .into_iter()
        .filter_map(Value::as_object)
        .map(|e| NativeEndpoint {
            uri: werte::text(e.get("uri")),
            pass_security_headers: werte::wahrheitswert(e.get("passSecurityHeaders"), false),
        })
        .collect()
}

/// Gemeinsamer Kern für ZIP und Verzeichnis.
struct Aufbau<'g> {
    grenzen: &'g Grenzen,
    api_raw: BTreeMap<String, (String, Objekt)>,
    aktionen: HashMap<String, Vec<(String, PolicyAction)>>,
    zuordnung: HashMap<String, HashSet<String>>,
    alias_dateien: HashMap<String, Vec<(String, Objekt)>>,
    uebersprungen: Vec<Uebersprungen>,
    gesperrt: usize,
    gelesen: u64,
}

impl<'g> Aufbau<'g> {
    fn neu(grenzen: &'g Grenzen) -> Self {
        Self {
            grenzen,
            api_raw: BTreeMap::new(),
            aktionen: HashMap::new(),
            zuordnung: HashMap::new(),
            alias_dateien: HashMap::new(),
            uebersprungen: Vec::new(),
            gesperrt: 0,
            gelesen: 0,
        }
    }

    /// Ein Eintrag des Exports. `lesen(n)` liefert höchstens `n` Bytes und wird
    /// nur für Asset-Kandidaten aufgerufen — **nie** für gesperrte Einträge.
    fn eintrag(
        &mut self,
        name: &str,
        lesen: impl FnOnce(u64) -> Result<Vec<u8>, Grund>,
    ) -> Result<(), ExportFehler> {
        let teile = teile(name);
        if ist_gesperrt(&teile) {
            self.gesperrt += 1;
            return Ok(());
        }
        let Some((art, schluessel)) = einordnen(&teile) else {
            return Ok(());
        };
        let pfad = teile.join("/");
        let raw = match self.lies(art, lesen)? {
            Ok(raw) => raw,
            Err(grund) => {
                self.uebersprungen.push(Uebersprungen { pfad, grund });
                return Ok(());
            }
        };
        match art {
            Art::Api => {
                self.api_raw.insert(schluessel, (pfad, raw));
            }
            Art::Aktion => {
                let aktion = PolicyAction::aus_json(&raw);
                self.aktionen
                    .entry(schluessel)
                    .or_default()
                    .push((pfad, aktion));
            }
            Art::Policy => {
                if let Some(ids) = zugeordnete_ids(&raw) {
                    self.zuordnung.entry(schluessel).or_default().extend(ids);
                }
            }
            Art::Alias => {
                self.alias_dateien
                    .entry(schluessel)
                    .or_default()
                    .push((pfad, raw));
            }
        }
        Ok(())
    }

    fn lies(
        &mut self,
        art: Art,
        lesen: impl FnOnce(u64) -> Result<Vec<u8>, Grund>,
    ) -> Result<Result<Objekt, Grund>, ExportFehler> {
        let daten = match lesen(self.grenzen.datei.saturating_add(1)) {
            Ok(d) => d,
            Err(grund) => return Ok(Err(grund)),
        };
        let laenge = u64::try_from(daten.len()).unwrap_or(u64::MAX);
        self.gelesen = self.gelesen.saturating_add(laenge);
        if self.gelesen > self.grenzen.gesamt {
            return Err(ExportFehler(format!(
                "Export überschreitet {} Bytes entpackte Asset-Daten",
                self.grenzen.gesamt
            )));
        }
        if laenge > self.grenzen.datei {
            return Ok(Err(Grund::ZuGross));
        }
        let raw = match dekodieren(&daten, self.grenzen) {
            Ok(raw) => raw,
            Err(grund) => return Ok(Err(grund)),
        };
        if art == Art::Api && !raw.contains_key("apiName") {
            return Ok(Err(Grund::OhneApiname));
        }
        Ok(Ok(raw))
    }

    fn fertig(mut self, quelle: &Path, art: &'static str, sha256: Option<String>) -> GatewayExport {
        let aliase_je_wurzel: HashMap<String, HashMap<String, String>> = self
            .alias_dateien
            .into_iter()
            .map(|(wurzel, dateien)| (wurzel, einfache_aliase(dateien)))
            .collect();

        let mut apis = Vec::new();
        for (api_pfad, (datei_pfad, raw)) in &self.api_raw {
            let mut eigene = self.aktionen.remove(api_pfad).unwrap_or_default();
            eigene.sort_by(|a, b| a.0.cmp(&b.0));
            let mut aktionen = Vec::new();
            for (pfad, aktion) in eigene {
                let zugeordnet = self
                    .zuordnung
                    .get(api_pfad)
                    .is_none_or(|ids| ids.contains(&aktion.id));
                if zugeordnet {
                    aktionen.push(aktion);
                } else {
                    self.uebersprungen.push(Uebersprungen {
                        pfad,
                        grund: Grund::NichtZugeordnet,
                    });
                }
            }
            apis.push(GatewayApi {
                id: werte::text(raw.get("id")),
                name: werte::text(raw.get("apiName")),
                version: werte::text_oder_none(raw.get("apiVersion")),
                native_endpoints: native_endpoints(raw.get("nativeEndpoint")),
                policy_actions: aktionen,
                source_path: datei_pfad.clone(),
                aliase: aliase_fuer(api_pfad, &aliase_je_wurzel),
            });
        }
        for (_, waisen) in self.aktionen {
            self.uebersprungen
                .extend(waisen.into_iter().map(|(pfad, _)| Uebersprungen {
                    pfad,
                    grund: Grund::OhneApi,
                }));
        }
        self.uebersprungen
            .sort_by(|a, b| (&a.pfad, a.grund.code()).cmp(&(&b.pfad, b.grund.code())));

        GatewayExport {
            apis,
            quelle: quelle.to_path_buf(),
            art,
            sha256,
            uebersprungen: self.uebersprungen,
            gesperrt: self.gesperrt,
        }
    }
}

/// Name → Wert aller `simple`-Aliase; bei Namensgleichheit gewinnt der erste Pfad.
fn einfache_aliase(mut dateien: Vec<(String, Objekt)>) -> HashMap<String, String> {
    dateien.sort_by(|a, b| a.0.cmp(&b.0));
    let mut aliase = HashMap::new();
    for (_, raw) in dateien {
        if werte::text(raw.get("type")) != "simple" {
            continue;
        }
        let name = werte::text(raw.get("name"));
        if !name.is_empty() && !aliase.contains_key(&name) {
            aliase.insert(name, werte::text(raw.get("value")));
        }
    }
    aliase
}

/// Die Aliase der nächstgelegenen Wurzel oberhalb der API.
fn aliase_fuer(
    api_pfad: &str,
    je_wurzel: &HashMap<String, HashMap<String, String>>,
) -> HashMap<String, String> {
    je_wurzel
        .iter()
        .filter(|(w, _)| w.is_empty() || api_pfad.starts_with(&format!("{w}/")))
        .max_by_key(|(w, _)| w.len())
        .map(|(_, aliase)| aliase.clone())
        .unwrap_or_default()
}

// ------------------------------------------------------------------ Verzeichnis

fn begrenzt_lesen(quelle: impl Read, n: u64) -> io::Result<Vec<u8>> {
    let mut puffer = Vec::new();
    quelle.take(n).read_to_end(&mut puffer)?;
    Ok(puffer)
}

fn relativ(root: &Path, voll: &Path) -> Option<String> {
    let rel = voll.strip_prefix(root).ok()?;
    let teile: Option<Vec<&str>> = rel.components().map(|c| c.as_os_str().to_str()).collect();
    Some(teile?.join("/"))
}

/// Reguläre Dateien unterhalb von `ordner`; Symlinks werden nie verfolgt.
///
/// In gesperrte Verzeichnisse wird nur hineingeschaut, um ihre Dateien zu
/// zählen — geöffnet wird dort nichts.
fn wandern(
    root: &Path,
    ordner: &Path,
    aufbau: &mut Aufbau<'_>,
    anzahl: &mut usize,
) -> Result<(), ExportFehler> {
    let Ok(eintraege) = fs::read_dir(ordner) else {
        return Ok(()); // wie os.walk: ein unlesbarer Ordner wird übergangen
    };
    let mut dateien = Vec::new();
    let mut unterordner = Vec::new();
    for eintrag in eintraege.flatten() {
        let Ok(typ) = eintrag.file_type() else {
            continue;
        };
        if typ.is_symlink() {
            // Ein Symlink auf ein Verzeichnis wird weder betreten noch gelesen.
            if !fs::metadata(eintrag.path()).is_ok_and(|m| m.is_dir()) {
                dateien.push(eintrag.file_name());
            }
        } else if typ.is_dir() {
            unterordner.push(eintrag.file_name());
        } else {
            dateien.push(eintrag.file_name());
        }
    }
    dateien.sort();
    unterordner.sort();

    for name in dateien {
        let voll = ordner.join(&name);
        let Ok(info) = fs::symlink_metadata(&voll) else {
            continue;
        };
        let Some(rel) = relativ(root, &voll) else {
            continue; // Dateiname ist kein gültiges UTF-8
        };
        if info.file_type().is_symlink() {
            aufbau.eintrag(&rel, |_| Err(Grund::Symlink))?;
            continue;
        }
        if !info.file_type().is_file() {
            continue; // FIFO, Gerät, Socket — Lesen könnte blockieren
        }
        *anzahl += 1;
        if *anzahl > aufbau.grenzen.eintraege {
            return Err(ExportFehler(format!(
                "Export enthält mehr als {} Dateien",
                aufbau.grenzen.eintraege
            )));
        }
        aufbau.eintrag(&rel, |n| {
            File::open(&voll)
                .and_then(|f| begrenzt_lesen(f, n))
                .map_err(|_| Grund::Lesefehler)
        })?;
    }
    for name in unterordner {
        wandern(root, &ordner.join(name), aufbau, anzahl)?;
    }
    Ok(())
}

/// Liest einen entpackten Export (oder ein ganzes Repository davon).
pub fn read_directory(root: &Path, grenzen: &Grenzen) -> Result<GatewayExport, ExportFehler> {
    if !root.is_dir() {
        return Err(ExportFehler(format!(
            "Export nicht gefunden: {}",
            root.display()
        )));
    }
    let mut aufbau = Aufbau::neu(grenzen);
    let mut anzahl = 0;
    wandern(root, root, &mut aufbau, &mut anzahl)?;
    Ok(aufbau.fertig(root, "verzeichnis", None))
}

// ------------------------------------------------------------------ ZIP

fn sha256_datei(pfad: &Path) -> io::Result<String> {
    let mut datei = BufReader::new(File::open(pfad)?);
    let mut hasher = Sha256::new();
    let mut puffer = vec![0u8; 1 << 20];
    loop {
        let n = datei.read(&mut puffer)?;
        let Some(block) = puffer.get(..n) else { break };
        if block.is_empty() {
            break;
        }
        hasher.update(block);
    }
    Ok(hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

/// Zählt die Einträge des zentralen Verzeichnisses selbst.
///
/// Das `zip`-Crate fasst gleichnamige Einträge stillschweigend zusammen. Zwei
/// Einträge mit demselben Namen sind ein bekannter Trick, um verschiedenen
/// Werkzeugen verschiedene Inhalte zu zeigen — sie führen zum Abbruch.
fn zentralverzeichnis_zaehlen(pfad: &Path, start: u64, obergrenze: usize) -> io::Result<usize> {
    let mut datei = BufReader::new(File::open(pfad)?);
    datei.seek(SeekFrom::Start(start))?;
    let mut anzahl = 0usize;
    let mut kopf = [0u8; 46];
    while anzahl <= obergrenze {
        if datei.read_exact(&mut kopf).is_err() || kopf[0..4] != *b"PK\x01\x02" {
            break;
        }
        // Längen von Name, Extra-Feld und Kommentar (Offsets 28, 30, 32).
        let name = u16::from_le_bytes([kopf[28], kopf[29]]);
        let extra = u16::from_le_bytes([kopf[30], kopf[31]]);
        let kommentar = u16::from_le_bytes([kopf[32], kopf[33]]);
        datei.seek_relative(i64::from(name) + i64::from(extra) + i64::from(kommentar))?;
        anzahl += 1;
    }
    Ok(anzahl)
}

fn zip_fehler(pfad: &Path) -> ExportFehler {
    ExportFehler(format!("Keine gültige ZIP-Datei: {}", pfad.display()))
}

/// Liest einen Export direkt aus dem ZIP, ohne ihn auf Platte zu entpacken.
pub fn read_zip(pfad: &Path, grenzen: &Grenzen) -> Result<GatewayExport, ExportFehler> {
    let sha = sha256_datei(pfad).map_err(|e| ExportFehler(format!("{}: {e}", pfad.display())))?;
    let datei = File::open(pfad).map_err(|e| ExportFehler(format!("{}: {e}", pfad.display())))?;
    let mut archiv = ZipArchive::new(datei).map_err(|_| zip_fehler(pfad))?;

    let eintraege =
        zentralverzeichnis_zaehlen(pfad, archiv.central_directory_start(), grenzen.eintraege)
            .map_err(|_| zip_fehler(pfad))?;
    if eintraege > grenzen.eintraege {
        return Err(ExportFehler(format!(
            "ZIP enthält mehr als {} Einträge",
            grenzen.eintraege
        )));
    }
    if eintraege != archiv.len() {
        return Err(ExportFehler(
            "ZIP enthält doppelte Eintragsnamen".to_owned(),
        ));
    }

    let mut aufbau = Aufbau::neu(grenzen);
    for i in 0..archiv.len() {
        let (name, lesbar) = {
            let eintrag = archiv.by_index_data(i).map_err(|_| zip_fehler(pfad))?;
            let name = eintrag.name().map_err(|_| zip_fehler(pfad))?.into_owned();
            let lesbar = !eintrag.encrypted()
                && matches!(
                    eintrag.compression(),
                    CompressionMethod::Stored | CompressionMethod::Deflated
                );
            (name, lesbar)
        };
        if name.ends_with('/') {
            continue;
        }
        if ist_gesperrt(&teile(&name)) {
            aufbau.gesperrt += 1; // gezählt, nie dekomprimiert
            continue;
        }
        aufbau.eintrag(&name, |n| {
            if !lesbar {
                return Err(Grund::Lesefehler); // verschlüsselt oder exotisch komprimiert
            }
            let inhalt = archiv.by_index(i).map_err(|_| Grund::Lesefehler)?;
            begrenzt_lesen(inhalt, n).map_err(|_| Grund::Lesefehler)
        })?;
    }
    Ok(aufbau.fertig(pfad, "zip", Some(sha)))
}

/// Liest einen Export — ZIP oder entpacktes Verzeichnis.
pub fn read_export(pfad: &Path, grenzen: &Grenzen) -> Result<GatewayExport, ExportFehler> {
    let nicht_gefunden = || ExportFehler(format!("Export nicht gefunden: {}", pfad.display()));
    let info = fs::metadata(pfad).map_err(|_| nicht_gefunden())?;
    if info.is_dir() {
        read_directory(pfad, grenzen)
    } else if info.is_file() {
        read_zip(pfad, grenzen)
    } else {
        Err(nicht_gefunden())
    }
}

/// Pfad, unter dem der Bericht die Quelle nennt (nur der letzte Teil).
pub fn quellname(quelle: &Path) -> String {
    fs::canonicalize(quelle)
        .unwrap_or_else(|_| PathBuf::from(quelle))
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sperrliste() {
        for (pfad, soll) in [
            (vec!["assets", "PassmanData", "x"], true),
            (vec!["keystore.jks"], true),
            (vec!["KERBEROS"], true),
            (vec!["\u{212a}eystore"], true), // Kelvin-Zeichen wird klein zu "k"
            (vec!["PassmanDataX"], false),
            (vec!["Keystores"], false),
            (vec!["API.Truststore"], false),
        ] {
            assert_eq!(ist_gesperrt(&pfad), soll, "{pfad:?}");
        }
    }

    #[test]
    fn einordnung() {
        let t = |s: &str| teile(s);
        assert_eq!(
            einordnen(&t("a/API/API.x/API.x")),
            Some((Art::Api, "a/API/API.x".into()))
        );
        assert_eq!(
            einordnen(&t("API.x/Policy/Policy.p/Policy.p")),
            Some((Art::Policy, "API.x".into()))
        );
        assert_eq!(
            einordnen(&t("API.a/u/API.i/P/PolicyAction.1")),
            Some((Art::Aktion, "API.a/u/API.i".into()))
        );
        assert_eq!(
            einordnen(&t("env/Alias/Alias.1")),
            Some((Art::Alias, "env".into()))
        );
        assert_eq!(einordnen(&t("API.x/._API.x")), None);
        assert_eq!(einordnen(&t("PolicyAction.1")), None);
        assert_eq!(
            einordnen(&t("win\\API\\API.w\\API.w")),
            Some((Art::Api, "win/API/API.w".into()))
        );
    }
}
