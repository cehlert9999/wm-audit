//! Bericht eines Laufs — als JSON, Text, HTML und JUnit-XML.
//!
//! Das JSON-Format `wm-audit-bericht/1` ist der Vertrag mit der Referenzimplementierung:
//! Schlüssel sortiert, zwei Leerzeichen Einzug, UTF-8 ohne ASCII-Escapes.

use std::collections::{HashMap, HashSet};

use serde_json::{Map, Value};

use crate::befund::{Finding, Severity};
use crate::lesen::quellname;
use crate::modell::{GatewayApi, GatewayExport, Lastgrenze, beschreibung};
use crate::regeln::{LAUFZEIT_LUECKEN, PRUEFREGELN, run_rules};

pub const FORMAT: &str = "wm-audit-bericht/1";

pub fn werkzeug() -> String {
    format!("wm-audit {}", crate::VERSION)
}

fn objekt<const N: usize>(paare: [(&str, Value); N]) -> Value {
    Value::Object(
        paare
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Map<_, _>>(),
    )
}

fn lastgrenze_json(g: &Lastgrenze) -> Value {
    objekt([
        ("aktion", g.aktion.as_str().into()),
        ("limit", g.limit.into()),
        ("intervall", g.intervall.into()),
        ("einheit", g.einheit.clone().into()),
        ("consumer", g.consumer.clone().into()),
        ("meldung", g.meldung.clone().into()),
    ])
}

fn befund_json(f: &Finding) -> Value {
    let evidence = f
        .evidence
        .iter()
        .map(|e| {
            objekt([
                ("pointer", e.pointer.as_str().into()),
                ("excerpt", e.excerpt.as_str().into()),
                ("note", e.note.as_str().into()),
            ])
        })
        .collect::<Vec<_>>();
    objekt([
        ("check_id", f.check_id.into()),
        ("title", f.title.as_str().into()),
        ("confidence", f.confidence.code().into()),
        ("severity", f.severity.code().into()),
        ("owasp", f.owasp.map(|o| o.code()).into()),
        ("scope", f.scope.code().into()),
        ("subject", f.subject.as_str().into()),
        ("method", Value::Null),
        ("reason", f.reason.as_str().into()),
        ("remediation", f.remediation.as_str().into()),
        ("evidence", evidence.into()),
        ("aggregate_count", f.aggregate_count.into()),
        ("affected", f.affected.clone().into()),
        ("dimension", "design".into()),
        ("cap", Value::Null),
        ("id", f.id().into()),
        ("bewertet", f.bewertet().into()),
    ])
}

/// Der vollständige Bericht als JSON-Wert.
pub fn bericht(export: &GatewayExport) -> Value {
    let befunde = run_rules(export);
    let mut schwere = Map::new();
    for s in Severity::ALLE {
        let anzahl = befunde.iter().filter(|f| f.severity == s).count();
        schwere.insert(s.code().to_owned(), anzahl.into());
    }
    let eindeutig = export
        .apis
        .iter()
        .map(GatewayApi::label)
        .collect::<HashSet<_>>()
        .len();

    objekt([
        ("format", FORMAT.into()),
        ("werkzeug", werkzeug().into()),
        (
            "quelle",
            objekt([
                ("name", quellname(&export.quelle).into()),
                ("art", export.art.into()),
                ("sha256", export.sha256.clone().into()),
            ]),
        ),
        (
            "zusammenfassung",
            objekt([
                ("apis_gelesen", export.apis.len().into()),
                ("apis_eindeutig", eindeutig.into()),
                ("befunde", befunde.len().into()),
                (
                    "belegt",
                    befunde.iter().filter(|f| f.bewertet()).count().into(),
                ),
                ("schwere", Value::Object(schwere)),
                ("uebersprungen", export.uebersprungen.len().into()),
                ("gesperrt", export.gesperrt.into()),
            ]),
        ),
        (
            "apis",
            export
                .apis
                .iter()
                .map(|a| {
                    objekt([
                        ("label", a.label().into()),
                        ("name", a.name.as_str().into()),
                        ("version", a.version.clone().into()),
                        ("id", a.id.as_str().into()),
                        ("pfad", a.source_path.as_str().into()),
                        (
                            "policies",
                            a.policy_actions
                                .iter()
                                .map(|x| Value::from(x.template_key.as_str()))
                                .collect::<Vec<_>>()
                                .into(),
                        ),
                        (
                            "lastgrenzen",
                            a.lastgrenzen()
                                .iter()
                                .map(lastgrenze_json)
                                .collect::<Vec<_>>()
                                .into(),
                        ),
                    ])
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        (
            "befunde",
            befunde.iter().map(befund_json).collect::<Vec<_>>().into(),
        ),
        (
            "laufzeit_luecken",
            LAUFZEIT_LUECKEN
                .iter()
                .map(|g| {
                    objekt([
                        ("key", g.key.into()),
                        ("title", g.title.into()),
                        ("owasp", g.owasp.code().into()),
                        ("why", g.why.into()),
                    ])
                })
                .collect::<Vec<_>>()
                .into(),
        ),
        (
            "uebersprungen",
            export
                .uebersprungen
                .iter()
                .map(|u| {
                    objekt([
                        ("pfad", u.pfad.as_str().into()),
                        ("grund", u.grund.code().into()),
                    ])
                })
                .collect::<Vec<_>>()
                .into(),
        ),
    ])
}

/// HTML-Vorlage, identisch mit der Vorlage der Referenzimplementierung.
const VORLAGE: &str = include_str!("bericht.html");

/// Selbsttragender HTML-Bericht: die Vorlage plus das JSON als Datenblock.
///
/// Jedes `<` im JSON wird als `\u003c` geschrieben — Werte aus dem Export können
/// den `<script>`-Block so nicht verlassen. Die Vorlage setzt alle Werte nur als
/// Text ein, nie als HTML, und lädt per Content-Security-Policy nichts nach.
pub fn als_html(b: &Value) -> String {
    let daten = als_json(b).replace('<', "\\u003c");
    VORLAGE.replacen("__WM_AUDIT_BERICHT__", &daten, 1)
}

/// Kanonisches JSON: Schlüssel sortiert, zwei Leerzeichen Einzug, Zeilenende.
pub fn als_json(b: &Value) -> String {
    let mut text = serde_json::to_string_pretty(b).unwrap_or_default();
    text.push('\n');
    text
}

fn feld<'a>(v: &'a Value, schluessel: &str) -> &'a Value {
    v.get(schluessel).unwrap_or(&Value::Null)
}

fn s<'a>(v: &'a Value, schluessel: &str) -> &'a str {
    feld(v, schluessel).as_str().unwrap_or("")
}

fn n(v: &Value, schluessel: &str) -> u64 {
    feld(v, schluessel).as_u64().unwrap_or(0)
}

fn liste<'a>(v: &'a Value, schluessel: &str) -> &'a [Value] {
    feld(v, schluessel)
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// Lesbarer Bericht für das Terminal.
pub fn als_text(b: &Value) -> String {
    let z = feld(b, "zusammenfassung");
    let q = feld(b, "quelle");
    let mut zeilen = vec![format!(
        "{} · {} ({})",
        s(b, "werkzeug"),
        s(q, "name"),
        s(q, "art")
    )];
    if let Some(sha) = feld(q, "sha256").as_str() {
        zeilen.push(format!("SHA-256: {sha}"));
    }
    zeilen.push(format!(
        "{} APIs gelesen ({} eindeutig) · {} Dateien übersprungen · {} gesperrte Einträge nicht geöffnet",
        n(z, "apis_gelesen"),
        n(z, "apis_eindeutig"),
        n(z, "uebersprungen"),
        n(z, "gesperrt"),
    ));
    zeilen.push(String::new());
    zeilen.push(format!(
        "Befunde: {} ({} belegt)",
        n(z, "befunde"),
        n(z, "belegt")
    ));
    for f in liste(b, "befunde") {
        zeilen.push(format!(
            "  {:<8}  {:<14}  {:<28}  {}",
            s(f, "severity").to_uppercase(),
            s(f, "confidence"),
            s(f, "check_id"),
            s(f, "subject"),
        ));
        zeilen.push(format!("            {}", s(f, "title")));
    }
    let grenzen: Vec<(&str, &Value)> = liste(b, "apis")
        .iter()
        .flat_map(|a| {
            liste(a, "lastgrenzen")
                .iter()
                .map(move |g| (s(a, "label"), g))
        })
        .collect();
    if !grenzen.is_empty() {
        zeilen.push(String::new());
        zeilen.push("Lastgrenzen (Traffic Optimization):".to_owned());
        for (label, g) in grenzen {
            let mut zeile = format!(
                "  {label}: {}",
                beschreibung(
                    feld(g, "limit").as_u64(),
                    feld(g, "intervall").as_u64(),
                    feld(g, "einheit").as_str()
                )
            );
            let consumer: Vec<&str> = liste(g, "consumer")
                .iter()
                .filter_map(Value::as_str)
                .collect();
            if !consumer.is_empty() {
                zeile.push_str(&format!(" · consumerIds: {}", consumer.join(", ")));
            }
            zeilen.push(zeile);
        }
    }
    let uebersprungen = liste(b, "uebersprungen");
    if !uebersprungen.is_empty() {
        zeilen.push(String::new());
        zeilen.push("Übersprungen:".to_owned());
        for u in uebersprungen {
            zeilen.push(format!("  {:<16}  {}", s(u, "grund"), s(u, "pfad")));
        }
    }
    let luecken = liste(b, "laufzeit_luecken");
    zeilen.push(String::new());
    zeilen.push(format!("Statisch nicht prüfbar ({}):", luecken.len()));
    for g in luecken {
        let owasp = feld(g, "owasp").as_str().unwrap_or("-");
        zeilen.push(format!("  {:<4}  {}", owasp, s(g, "title")));
    }
    let mut text = zeilen.join("\n");
    text.push('\n');
    text
}

/// Ein **belegter** Befund mit mindestens dieser Schwere.
fn loest_aus(f: &Value, schwelle: Severity) -> bool {
    feld(f, "bewertet").as_bool().unwrap_or(false)
        && Severity::aus_code(s(f, "severity")).is_some_and(|sev| sev <= schwelle)
}

/// Gibt es einen **belegten** Befund mit mindestens dieser Schwere?
pub fn ueber_schwelle(b: &Value, schwelle: Severity) -> bool {
    liste(b, "befunde").iter().any(|f| loest_aus(f, schwelle))
}

// ------------------------------------------------------------------ JUnit

/// Text für XML 1.0: maskiert und ohne Zeichen, die XML nicht erlaubt (→ U+FFFD).
///
/// In Attributen bleiben Zeilenumbruch und Tabulator als Zeichenreferenz erhalten,
/// sonst würde ein XML-Parser sie zu Leerzeichen normalisieren.
fn xml(text: &str, attribut: bool) -> String {
    let mut aus = String::with_capacity(text.len());
    for z in text.chars() {
        let c = u32::from(z);
        let erlaubt = matches!(c, 0x9 | 0xA | 0xD | 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x1_0000..);
        let z = if erlaubt { z } else { '\u{FFFD}' };
        match z {
            '&' => aus.push_str("&amp;"),
            '<' => aus.push_str("&lt;"),
            '>' => aus.push_str("&gt;"),
            '\r' => aus.push_str("&#13;"),
            '"' if attribut => aus.push_str("&quot;"),
            '\n' if attribut => aus.push_str("&#10;"),
            '\t' if attribut => aus.push_str("&#9;"),
            _ => aus.push(z),
        }
    }
    aus
}

fn befund_text(f: &Value) -> String {
    let mut zeilen = vec![
        format!(
            "[{}, {}] {}",
            s(f, "severity").to_uppercase(),
            s(f, "confidence"),
            s(f, "title")
        ),
        s(f, "reason").to_owned(),
    ];
    if !s(f, "remediation").is_empty() {
        zeilen.push(format!("Empfehlung: {}", s(f, "remediation")));
    }
    for e in liste(f, "evidence") {
        let mut teile = vec![format!("Fundstelle: {}", s(e, "pointer"))];
        teile.extend(
            ["excerpt", "note"]
                .iter()
                .map(|k| s(e, k))
                .filter(|w| !w.is_empty())
                .map(str::to_owned),
        );
        zeilen.push(teile.join(" | "));
    }
    zeilen.join("\n")
}

struct Suite {
    name: String,
    tests: usize,
    fehler: usize,
    uebersprungen: usize,
    zeilen: Vec<String>,
}

/// Bericht als JUnit-XML für CI-Systeme.
///
/// Je API eine Testsuite mit einem Testfall pro Prüfregel; Name des Testfalls ist
/// die Regel-ID. Fehlgeschlagen ist ein Testfall genau dann, wenn ein Befund dieser
/// Regel die API trifft — mit `--fail-on` nur, wenn der Befund auch den Exit-Code 1
/// auslöst; die übrigen Befunde stehen dann in `system-out`.
pub fn als_junit(b: &Value, fail_on: Option<Severity>) -> String {
    let mut labels: Vec<&str> = Vec::new();
    let mut gesehen = HashSet::new();
    for a in liste(b, "apis") {
        if gesehen.insert(s(a, "label")) {
            labels.push(s(a, "label"));
        }
    }
    let mut treffer: HashMap<(&str, &str), Vec<&Value>> = HashMap::new();
    for f in liste(b, "befunde") {
        let betroffen: Vec<&str> = if feld(f, "aggregate_count").is_null() {
            vec![s(f, "subject")]
        } else {
            liste(f, "affected")
                .iter()
                .filter_map(Value::as_str)
                .collect()
        };
        for label in betroffen {
            treffer
                .entry((label, s(f, "check_id")))
                .or_default()
                .push(f);
        }
    }

    let mut suiten = Vec::new();
    let (q, z) = (feld(b, "quelle"), feld(b, "zusammenfassung"));
    let mut eigenschaften = vec![
        ("werkzeug", s(b, "werkzeug").to_owned()),
        ("quelle", s(q, "name").to_owned()),
        ("art", s(q, "art").to_owned()),
    ];
    if let Some(sha) = feld(q, "sha256").as_str().filter(|w| !w.is_empty()) {
        eigenschaften.push(("sha256", sha.to_owned()));
    }
    if let Some(schwelle) = fail_on {
        eigenschaften.push(("fail_on", schwelle.code().to_owned()));
    }
    for k in [
        "apis_gelesen",
        "apis_eindeutig",
        "gesperrt",
        "uebersprungen",
    ] {
        eigenschaften.push((k, n(z, k).to_string()));
    }
    let mut zeilen = vec!["    <properties>".to_owned()];
    zeilen.extend(
        eigenschaften
            .iter()
            .map(|(k, v)| format!("      <property name=\"{k}\" value=\"{}\"/>", xml(v, true))),
    );
    zeilen.push("    </properties>".to_owned());
    let uebersprungen = liste(b, "uebersprungen");
    for u in uebersprungen {
        zeilen.push(format!(
            "    <testcase classname=\"wm-audit.export\" name=\"{}\">",
            xml(s(u, "pfad"), true)
        ));
        zeilen.push(format!(
            "      <skipped message=\"{}\"/>",
            xml(s(u, "grund"), true)
        ));
        zeilen.push("    </testcase>".to_owned());
    }
    suiten.push(Suite {
        name: "Export".to_owned(),
        tests: uebersprungen.len(),
        fehler: 0,
        uebersprungen: uebersprungen.len(),
        zeilen,
    });

    for label in labels {
        let klasse = format!("wm-audit.{}", label.replace('.', "_"));
        let (mut zeilen, mut fehler_zahl) = (Vec::new(), 0);
        for regel in PRUEFREGELN {
            let befunde = treffer.get(&(label, regel)).cloned().unwrap_or_default();
            let mut fehler: Vec<&Value> = befunde
                .iter()
                .copied()
                .filter(|f| fail_on.is_none_or(|schwelle| loest_aus(f, schwelle)))
                .collect();
            fehler.sort_by_key(|f| Severity::aus_code(s(f, "severity")));
            let hinweise: Vec<&Value> = match fail_on {
                Some(schwelle) => befunde
                    .iter()
                    .copied()
                    .filter(|f| !loest_aus(f, schwelle))
                    .collect(),
                None => Vec::new(),
            };
            let kopf = format!(
                "    <testcase classname=\"{}\" name=\"{regel}\"",
                xml(&klasse, true)
            );
            if fehler.is_empty() && hinweise.is_empty() {
                zeilen.push(format!("{kopf}/>"));
                continue;
            }
            zeilen.push(format!("{kopf}>"));
            if let Some(erster) = fehler.first() {
                fehler_zahl += 1;
                let text = fehler
                    .iter()
                    .map(|f| befund_text(f))
                    .collect::<Vec<_>>()
                    .join("\n\n");
                zeilen.push(format!(
                    "      <failure type=\"{}\" message=\"{}\">{}</failure>",
                    s(erster, "severity"),
                    xml(s(erster, "title"), true),
                    xml(&text, false)
                ));
            }
            if let (false, Some(schwelle)) = (hinweise.is_empty(), fail_on) {
                let text = format!(
                    "Unterhalb der Schwelle --fail-on {}:\n\n{}",
                    schwelle.code(),
                    hinweise
                        .iter()
                        .map(|f| befund_text(f))
                        .collect::<Vec<_>>()
                        .join("\n\n")
                );
                zeilen.push(format!(
                    "      <system-out>{}</system-out>",
                    xml(&text, false)
                ));
            }
            zeilen.push("    </testcase>".to_owned());
        }
        suiten.push(Suite {
            name: format!("API: {label}"),
            tests: PRUEFREGELN.len(),
            fehler: fehler_zahl,
            uebersprungen: 0,
            zeilen,
        });
    }

    let luecken = liste(b, "laufzeit_luecken");
    let mut zeilen = Vec::new();
    for g in luecken {
        zeilen.push(format!(
            "    <testcase classname=\"wm-audit.laufzeit\" name=\"{}\">",
            s(g, "key")
        ));
        zeilen.push(format!(
            "      <skipped message=\"{}\"/>",
            xml(&format!("{} {}", s(g, "title"), s(g, "why")), true)
        ));
        zeilen.push("    </testcase>".to_owned());
    }
    suiten.push(Suite {
        name: "Statisch nicht prüfbar".to_owned(),
        tests: luecken.len(),
        fehler: 0,
        uebersprungen: luecken.len(),
        zeilen,
    });

    // „skipped“ steht nur an den Testsuiten; das Jenkins-Schema erlaubt es nicht an testsuites.
    let tests: usize = suiten.iter().map(|x| x.tests).sum();
    let fehler: usize = suiten.iter().map(|x| x.fehler).sum();
    let mut aus = vec![
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>".to_owned(),
        format!(
            "<testsuites name=\"wm-audit\" tests=\"{tests}\" failures=\"{fehler}\" errors=\"0\">"
        ),
    ];
    for suite in suiten {
        aus.push(format!(
            "  <testsuite name=\"{}\" tests=\"{}\" failures=\"{}\" errors=\"0\" skipped=\"{}\">",
            xml(&suite.name, true),
            suite.tests,
            suite.fehler,
            suite.uebersprungen
        ));
        aus.extend(suite.zeilen);
        aus.push("  </testsuite>".to_owned());
    }
    aus.push("</testsuites>".to_owned());
    let mut text = aus.join("\n");
    text.push('\n');
    text
}
