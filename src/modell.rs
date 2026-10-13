//! Datenmodell eines eingelesenen Exports.
//!
//! Übernommen wird nur, was eine Regel oder der Bericht braucht. Das Feld
//! `active` einer Policy-Aktion fehlt bewusst: es steht in Exporten durchgehend
//! auf `false` (Serialisierungsartefakt). Was nicht im Modell steht, kann keine
//! Regel versehentlich auswerten.

use std::collections::HashMap;
use std::path::PathBuf;

use serde_json::Value;

use crate::werte::{self, Objekt};

/// Eine einzelne Policy-Aktion, z. B. „Identify & Authorize“.
#[derive(Debug, Clone)]
pub struct PolicyAction {
    pub id: String,
    pub name: String,
    pub template_key: String,
    parameters: Vec<Objekt>,
}

fn ist_schluessel(p: &Objekt, key: &str) -> bool {
    matches!(p.get("templateKey"), Some(Value::String(s)) if s == key)
}

impl PolicyAction {
    pub fn aus_json(raw: &Objekt) -> Self {
        Self {
            id: werte::text(raw.get("id")),
            name: werte::lokalisiert(raw.get("names")),
            template_key: werte::text(raw.get("templateKey")),
            parameters: werte::objekte(raw.get("parameters"))
                .into_iter()
                .cloned()
                .collect(),
        }
    }

    /// Alle Werte eines direkten Parameters.
    pub fn values(&self, key: &str) -> Vec<String> {
        self.parameters
            .iter()
            .find(|p| ist_schluessel(p, key))
            .map(|p| werte::text_liste(p.get("values")))
            .unwrap_or_default()
    }

    /// Erster Wert eines direkten Parameters.
    pub fn value(&self, key: &str) -> Option<String> {
        self.values(key).into_iter().next()
    }

    /// Verschachtelte Parameter-Gruppen, z. B. jede `IdentificationRule`.
    pub fn groups(&self, key: &str) -> Vec<&Objekt> {
        self.parameters
            .iter()
            .filter(|p| ist_schluessel(p, key))
            .collect()
    }

    pub fn group_values(group: &Objekt, key: &str) -> Vec<String> {
        werte::objekte(group.get("parameters"))
            .into_iter()
            .find(|p| ist_schluessel(p, key))
            .map(|p| werte::text_liste(p.get("values")))
            .unwrap_or_default()
    }
}

/// Dauer je Einheit der Traffic-Optimization-Policy in Sekunden — die Werte aus
/// der offiziellen IBM-Postman-Collection. „Calendar Week“ und „Calendar Month“
/// der Oberfläche sind im Export nicht belegt und bleiben ohne Dauer.
fn einheit_sekunden(einheit: &str) -> Option<u64> {
    match einheit {
        "minutes" => Some(60),
        "hours" => Some(3600),
        "days" => Some(86_400),
        "weeks" => Some(604_800),
        _ => None,
    }
}

fn einheit_text(einheit: &str) -> Option<(&'static str, &'static str)> {
    match einheit {
        "minutes" => Some(("Minute", "Minuten")),
        "hours" => Some(("Stunde", "Stunden")),
        "days" => Some(("Tag", "Tage")),
        "weeks" => Some(("Woche", "Wochen")),
        _ => None,
    }
}

/// `100000` → `100.000`.
pub fn tausender(n: u64) -> String {
    let ziffern = n.to_string();
    let laenge = ziffern.len();
    let mut aus = String::with_capacity(laenge + laenge / 3);
    for (i, z) in ziffern.chars().enumerate() {
        if i > 0 && (laenge - i).is_multiple_of(3) {
            aus.push('.');
        }
        aus.push(z);
    }
    aus
}

/// `(1, "days")` → `je Tag`, `(5, "minutes")` → `je 5 Minuten`.
pub fn je_zeitraum(intervall: Option<u64>, einheit: Option<&str>) -> Option<String> {
    let (intervall, einheit) = (intervall?, einheit?);
    Some(match einheit_text(einheit) {
        Some((einzahl, _)) if intervall == 1 => format!("je {einzahl}"),
        Some((_, mehrzahl)) => format!("je {} {mehrzahl}", tausender(intervall)),
        None => format!("je {} {einheit}", tausender(intervall)),
    })
}

/// Eine Lastgrenze in einem Satzteil, z. B. `1.000 Aufrufe je Minute`.
pub fn beschreibung(limit: Option<u64>, intervall: Option<u64>, einheit: Option<&str>) -> String {
    let Some(limit) = limit else {
        return "Grenze nicht lesbar".to_owned();
    };
    match je_zeitraum(intervall, einheit) {
        Some(je) => format!("{} Aufrufe {je}", tausender(limit)),
        None => format!("{} Aufrufe, Intervall nicht lesbar", tausender(limit)),
    }
}

/// Was eine Traffic-Optimization-Policy (`throttle`) erlaubt — Felder nach der
/// offiziellen IBM-Postman-Collection. Was nicht eindeutig lesbar ist, bleibt
/// `None`; geraten wird nicht.
#[derive(Debug, Clone)]
pub struct Lastgrenze {
    pub aktion: String,
    pub limit: Option<u64>,
    pub intervall: Option<u64>,
    pub einheit: Option<String>,
    /// Roh aus `consumerIds`; die Zuordnung zu den Optionen der Oberfläche ist
    /// nicht dokumentiert.
    pub consumer: Vec<String>,
    /// `alertMessage` — der Text, den der Aufrufer mit dem 429 erhält.
    pub meldung: Option<String>,
}

impl Lastgrenze {
    pub fn fenster_sekunden(&self) -> Option<u64> {
        let intervall = self.intervall.filter(|i| *i >= 1)?;
        let sekunden = einheit_sekunden(self.einheit.as_deref()?)?;
        Some(intervall.saturating_mul(sekunden))
    }
}

fn erster_ist(werte: &[String], soll: &str) -> bool {
    werte.first().is_some_and(|w| w == soll)
}

pub fn lastgrenze(a: &PolicyAction) -> Lastgrenze {
    let limit = a
        .groups("throttleRule")
        .into_iter()
        .find(|regel| {
            erster_ist(
                &PolicyAction::group_values(regel, "throttleRuleName"),
                "requestCount",
            ) && erster_ist(
                &PolicyAction::group_values(regel, "monitorRuleOperator"),
                "GT",
            )
        })
        .and_then(|regel| {
            PolicyAction::group_values(regel, "value")
                .first()
                .and_then(|w| werte::anzahl(w))
        });
    Lastgrenze {
        aktion: a.name.clone(),
        limit,
        intervall: a.value("alertInterval").and_then(|w| werte::anzahl(&w)),
        einheit: a.value("alertIntervalUnit"),
        consumer: a.values("consumerIds"),
        meldung: a.value("alertMessage"),
    }
}

/// Ein Server-Eintrag der importierten Spec (`nativeEndpoint`).
#[derive(Debug, Clone)]
pub struct NativeEndpoint {
    pub uri: String,
    pub pass_security_headers: bool,
}

impl NativeEndpoint {
    pub fn is_plaintext(&self) -> bool {
        self.uri.to_lowercase().starts_with("http://")
    }
}

/// Eine im Gateway konfigurierte API samt zugeordneten Policies.
#[derive(Debug, Clone)]
pub struct GatewayApi {
    pub id: String,
    pub name: String,
    pub version: Option<String>,
    pub native_endpoints: Vec<NativeEndpoint>,
    pub policy_actions: Vec<PolicyAction>,
    /// Herkunft im Export, für die Evidence-Angabe im Befund.
    pub source_path: String,
    /// Einfache Aliase (`type: simple`) aus demselben Export: Name → Wert.
    pub aliase: HashMap<String, String>,
}

impl GatewayApi {
    pub fn label(&self) -> String {
        match &self.version {
            Some(v) if !v.is_empty() => format!("{} {}", self.name, v),
            _ => self.name.clone(),
        }
    }

    pub fn actions(&self, key: &str) -> Vec<&PolicyAction> {
        self.policy_actions
            .iter()
            .filter(|a| a.template_key == key)
            .collect()
    }

    pub fn has_action(&self, key: &str) -> bool {
        self.policy_actions.iter().any(|a| a.template_key == key)
    }

    /// Je Traffic-Optimization-Policy (`throttle`) eine Lastgrenze.
    pub fn lastgrenzen(&self) -> Vec<Lastgrenze> {
        self.actions("throttle")
            .into_iter()
            .map(lastgrenze)
            .collect()
    }

    /// Ist überhaupt eine Routing-Policy zugeordnet (gleich welcher Art)?
    pub fn hat_routing(&self) -> bool {
        self.policy_actions
            .iter()
            .any(|a| a.template_key.to_lowercase().contains("routing"))
    }

    /// `(Aktion, endpointUri wie konfiguriert, mit Aliasen aufgelöst)`.
    ///
    /// Ausgewertet wird nur `straightThroughRouting`; andere Routing-Arten sind
    /// in keinem vorliegenden Export belegt.
    pub fn routing_ziele(&self) -> Vec<(&PolicyAction, String, String)> {
        self.actions("straightThroughRouting")
            .into_iter()
            .flat_map(|a| {
                a.values("endpointUri").into_iter().map(move |uri| {
                    let aufgeloest = aufloesen(&uri, &self.aliase);
                    (a, uri, aufgeloest)
                })
            })
            .collect()
    }
}

/// Ersetzt `${Name}` durch den Alias-Wert; Unbekanntes bleibt stehen.
///
/// Ein Durchgang, keine Rekursion. `${sys:resource_path}` bleibt als
/// Systemvariable stehen.
pub fn aufloesen(uri: &str, aliase: &HashMap<String, String>) -> String {
    let mut ergebnis = String::with_capacity(uri.len());
    let mut rest = uri;
    loop {
        let Some((vor, nach)) = rest.split_once("${") else {
            ergebnis.push_str(rest);
            break;
        };
        let Some((name, danach)) = nach.split_once('}') else {
            ergebnis.push_str(rest);
            break;
        };
        ergebnis.push_str(vor);
        match aliase.get(name) {
            Some(wert) => ergebnis.push_str(wert),
            None => {
                ergebnis.push_str("${");
                ergebnis.push_str(name);
                ergebnis.push('}');
            }
        }
        rest = danach;
    }
    ergebnis
}

/// Warum eine Datei, die wie ein Asset aussieht, nicht ausgewertet wurde.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grund {
    ZuGross,
    KeinUtf8,
    ZuTief,
    KeinJson,
    KeinObjekt,
    OhneApiname,
    OhneApi,
    NichtZugeordnet,
    Lesefehler,
    Symlink,
}

impl Grund {
    /// Stabiler Code, wie er im Bericht steht.
    pub fn code(self) -> &'static str {
        match self {
            Grund::ZuGross => "zu_gross",
            Grund::KeinUtf8 => "kein_utf8",
            Grund::ZuTief => "zu_tief",
            Grund::KeinJson => "kein_json",
            Grund::KeinObjekt => "kein_objekt",
            Grund::OhneApiname => "ohne_apiname",
            Grund::OhneApi => "ohne_api",
            Grund::NichtZugeordnet => "nicht_zugeordnet",
            Grund::Lesefehler => "lesefehler",
            Grund::Symlink => "symlink",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Uebersprungen {
    pub pfad: String,
    pub grund: Grund,
}

/// Ein eingelesener Export.
#[derive(Debug)]
pub struct GatewayExport {
    pub apis: Vec<GatewayApi>,
    pub quelle: PathBuf,
    /// `zip` oder `verzeichnis`.
    pub art: &'static str,
    /// SHA-256 der ZIP-Datei — belegt im Bericht, welche Datei geprüft wurde.
    pub sha256: Option<String>,
    pub uebersprungen: Vec<Uebersprungen>,
    /// Zahl der Einträge mit Zugangsdaten/Schlüsseln, die nie geöffnet wurden.
    pub gesperrt: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aufloesen_wie_referenz() {
        let aliase = HashMap::from([("A".to_owned(), "http://a".to_owned())]);
        for (uri, soll) in [
            ("${A}/x", "http://a/x"),
            ("${sys:resource_path}", "${sys:resource_path}"),
            ("${A", "${A"),
            ("${a${A}}", "${a${A}}"),
            ("${A}${A}", "http://ahttp://a"),
            ("", ""),
        ] {
            assert_eq!(aufloesen(uri, &aliase), soll);
        }
    }
}
