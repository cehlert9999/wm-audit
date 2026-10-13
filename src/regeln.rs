//! Prüfregeln für eine Gateway-Konfiguration.
//!
//! Zwei Regeln gelten für den ganzen Katalog:
//!
//! 1. Kein Befund stützt sich auf das `active`-Feld einer Policy-Aktion; es ist
//!    nicht einmal im Modell (siehe `modell.rs`).
//! 2. Eine Regel, die bei mehr als der Hälfte aller APIs anschlägt, wird zu
//!    einem Aggregat zusammengefasst (siehe [`aggregate`]).
//!
//! Die Texte sind wortgleich mit der Referenzimplementierung; die Prüffälle sichern das.

use std::collections::{BTreeSet, HashSet};

use crate::befund::{Confidence, Evidence, Finding, Owasp, Scope, Severity, aggregate};
use crate::modell::{GatewayApi, GatewayExport, PolicyAction, beschreibung, lastgrenze};

type Regel = fn(&GatewayApi) -> Vec<Finding>;

/// Kennungen aller Prüfregeln in der Reihenfolge von [`REGELN`]. Der JUnit-Bericht
/// legt je API einen Testfall pro Regel an — auch für Regeln ohne Befund.
pub const PRUEFREGELN: [&str; 10] = [
    "gw.no_identify_policy",
    "gw.anonymous_allowed",
    "gw.identify_or",
    "gw.application_identity_only",
    "gw.http_allowed",
    "gw.plaintext_backend",
    "gw.pass_security_headers",
    "gw.no_traffic_limit",
    "gw.throttle_long_window",
    "gw.log_invocation",
];

/// Alle Regeln in fester Reihenfolge — sie bestimmt, welcher von zwei gleichen
/// Befunden beim Deduplizieren bleibt.
const REGELN: [Regel; 10] = [
    keine_identify_policy,
    anonymer_zugriff,
    identifikation_oder_verknuepft,
    nur_application_identitaet,
    http_erlaubt,
    klartext_backend,
    security_header_durchgereicht,
    fehlende_threat_protection,
    langes_kontingent,
    log_invocation,
];

struct Vorlage {
    check_id: &'static str,
    title: &'static str,
    confidence: Confidence,
    severity: Severity,
    owasp: Owasp,
    remediation: &'static str,
}

fn befund(api: &GatewayApi, v: &Vorlage, reason: String, evidence: Evidence) -> Finding {
    Finding {
        check_id: v.check_id,
        title: v.title.to_owned(),
        confidence: v.confidence,
        severity: v.severity,
        owasp: Some(v.owasp),
        scope: Scope::Api,
        subject: api.label(),
        reason,
        remediation: v.remediation.to_owned(),
        evidence: vec![evidence],
        aggregate_count: None,
        affected: Vec::new(),
    }
}

fn beleg(pointer: String, excerpt: String) -> Evidence {
    Evidence {
        pointer,
        excerpt,
        note: String::new(),
    }
}

fn zeiger(api: &GatewayApi, a: &PolicyAction) -> String {
    format!("{} → {}", api.source_path, a.name)
}

/// `http://user:pw@host/x` → `http://***@host/x`.
///
/// Ein Routing-Ziel oder Alias kann Zugangsdaten in der URL tragen. In einen
/// Bericht, der weitergegeben wird, gehören sie nicht.
pub fn ohne_zugangsdaten(uri: &str) -> String {
    let Some(i) = uri.find("://") else {
        return uri.to_owned();
    };
    let start = i + 3;
    let (vor, rest) = uri.split_at(start);
    let ende = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (autoritaet, _) = rest.split_at(ende);
    match autoritaet.rfind('@') {
        Some(at) => {
            let (_, ab_at) = rest.split_at(at);
            format!("{vor}***{ab_at}")
        }
        None => uri.to_owned(),
    }
}

// --------------------------------------------------------------- Identität

const KEINE_IDENTIFY: Vorlage = Vorlage {
    check_id: "gw.no_identify_policy",
    title: "API ohne Identify-and-Authorize-Policy",
    confidence: Confidence::Belegt,
    severity: Severity::High,
    owasp: Owasp::Api2,
    remediation: "Im Policy-Stage „Identify and Access“ eine Identify-and-Authorize-Policy \
                  einrichten. Ist die API bewusst öffentlich, sollte das dokumentiert und \
                  durch Threat-Protection und Rate-Limits abgesichert sein.",
};

/// Ohne „Identify & Authorize“ nimmt das Gateway jeden Aufrufer an.
fn keine_identify_policy(api: &GatewayApi) -> Vec<Finding> {
    if api.has_action("evaluatePolicy") {
        return Vec::new();
    }
    let schluessel: BTreeSet<&str> = api
        .policy_actions
        .iter()
        .map(|a| a.template_key.as_str())
        .collect();
    vec![befund(
        api,
        &KEINE_IDENTIFY,
        "Für diese API ist keine Identify-and-Authorize-Policy konfiguriert. \
         Das Gateway identifiziert den Aufrufer damit nicht und reicht jede \
         Anfrage an das Backend weiter."
            .to_owned(),
        Evidence {
            pointer: api.source_path.clone(),
            excerpt: format!(
                "policyActions: {}",
                schluessel.into_iter().collect::<Vec<_>>().join(", ")
            ),
            note: "kein evaluatePolicy vorhanden".to_owned(),
        },
    )]
}

const ANONYM: Vorlage = Vorlage {
    check_id: "gw.anonymous_allowed",
    title: "Identify-Policy erlaubt anonymen Zugriff",
    confidence: Confidence::Belegt,
    severity: Severity::Critical,
    owasp: Owasp::Api2,
    remediation: "allowAnonymous auf false setzen.",
};

/// `allowAnonymous` hebt die Identifikation wieder auf.
fn anonymer_zugriff(api: &GatewayApi) -> Vec<Finding> {
    api.actions("evaluatePolicy")
        .into_iter()
        .filter(|a| a.value("allowAnonymous").unwrap_or_default().to_lowercase() == "true")
        .map(|a| {
            befund(
                api,
                &ANONYM,
                "Die Identify-and-Authorize-Policy ist konfiguriert, lässt über \
                 allowAnonymous aber Anfragen ohne Identifikation durch. Die Policy \
                 sieht in der Oberfläche vorhanden aus und greift trotzdem nicht."
                    .to_owned(),
                beleg(zeiger(api, a), "allowAnonymous: true".to_owned()),
            )
        })
        .collect()
}

const ODER: Vorlage = Vorlage {
    check_id: "gw.identify_or",
    title: "Mehrere Identifikationsverfahren sind ODER-verknüpft",
    confidence: Confidence::Belegt,
    severity: Severity::High,
    owasp: Owasp::Api2,
    remediation: "logicalConnector auf AND setzen, wenn beide Nachweise verlangt sind. \
                  Ist ODER beabsichtigt, muss jedes einzelne Verfahren für sich als \
                  ausreichend gelten.",
};

/// Mehrere Identifier mit ODER — das schwächste Glied entscheidet.
fn identifikation_oder_verknuepft(api: &GatewayApi) -> Vec<Finding> {
    let mut befunde = Vec::new();
    for a in api.actions("evaluatePolicy") {
        let rules = a.groups("IdentificationRule");
        if rules.len() < 2
            || a.value("logicalConnector")
                .unwrap_or_default()
                .to_uppercase()
                != "OR"
        {
            continue;
        }
        let typen: Vec<String> = rules
            .iter()
            .flat_map(|r| PolicyAction::group_values(r, "identificationType"))
            .collect();
        befunde.push(befund(
            api,
            &ODER,
            format!(
                "Die Policy akzeptiert {} — es genügt also das \
                 schwächste dieser Verfahren. Wo API-Key *und* Token gemeint waren, \
                 reicht dann der API-Key allein.",
                typen.join(" oder ")
            ),
            beleg(
                zeiger(api, a),
                format!(
                    "logicalConnector: OR, identificationType: {}",
                    typen.join(", ")
                ),
            ),
        ));
    }
    befunde
}

const NUR_ANWENDUNG: Vorlage = Vorlage {
    check_id: "gw.application_identity_only",
    title: "Nur Anwendungs-Identifikation, keine Benutzer-Authentifizierung",
    confidence: Confidence::Wahrscheinlich,
    severity: Severity::Medium,
    owasp: Owasp::Api2,
    remediation: "Prüfen, ob das Backend die Benutzeridentität selbst auswertet. \
                  Für benutzerbezogene Daten zusätzlich OAuth2 oder JWT verlangen.",
};

/// API-Key identifiziert eine Anwendung, nicht einen Benutzer.
fn nur_application_identitaet(api: &GatewayApi) -> Vec<Finding> {
    // hostNameAddress: Wert aus der offiziellen IBM-Postman-Collection;
    // hostName bleibt für ältere Fixtures erhalten.
    // hostNameAddress: Wert aus der offiziellen IBM-Postman-Collection;
    // hostName bleibt für ältere Fixtures erhalten.
    const NUR_ANWENDUNG_TYPEN: [&str; 4] =
        ["apiKey", "hostNameAddress", "hostName", "ipAddressRange"];
    let mut befunde = Vec::new();
    for a in api.actions("evaluatePolicy") {
        let typen: BTreeSet<String> = a
            .groups("IdentificationRule")
            .iter()
            .flat_map(|r| PolicyAction::group_values(r, "identificationType"))
            .collect();
        if typen.is_empty()
            || !typen
                .iter()
                .all(|t| NUR_ANWENDUNG_TYPEN.contains(&t.as_str()))
        {
            continue;
        }
        let liste = typen.into_iter().collect::<Vec<_>>().join(", ");
        befunde.push(befund(
            api,
            &NUR_ANWENDUNG,
            format!(
                "Identifiziert wird ausschließlich über {liste}. \
                 Das weist eine Anwendung aus, nicht den handelnden Benutzer — jede \
                 benutzerbezogene Autorisierung muss dann vollständig im Backend \
                 stattfinden."
            ),
            beleg(zeiger(api, a), format!("identificationType: {liste}")),
        ));
    }
    befunde
}

// --------------------------------------------------------------- Transport

const HTTP: Vorlage = Vorlage {
    check_id: "gw.http_allowed",
    title: "Gateway akzeptiert unverschlüsseltes HTTP",
    confidence: Confidence::Belegt,
    severity: Severity::High,
    owasp: Owasp::Api8,
    remediation: "Nur HTTPS zulassen und HTTP an der Kante umleiten oder abweisen.",
};

/// Das Gateway nimmt unverschlüsselte Anfragen an.
fn http_erlaubt(api: &GatewayApi) -> Vec<Finding> {
    let mut befunde = Vec::new();
    for a in api.actions("entryProtocolPolicy") {
        let protos: Vec<String> = a
            .values("protocol")
            .iter()
            .map(|p| p.to_lowercase())
            .collect();
        if protos.iter().any(|p| p == "http") {
            befunde.push(befund(
                api,
                &HTTP,
                "Die Entry-Protocol-Policy lässt HTTP zu. Zugangsdaten und Nutzdaten \
                 sind auf dem Weg zum Gateway mitlesbar."
                    .to_owned(),
                beleg(zeiger(api, a), format!("protocol: {}", protos.join(", "))),
            ));
        }
    }
    befunde
}

const KLARTEXT: Vorlage = Vorlage {
    check_id: "gw.plaintext_backend",
    title: "Weiterleitung an ein Klartext-Backend",
    confidence: Confidence::Belegt,
    severity: Severity::High,
    owasp: Owasp::Api8,
    remediation: "Das Backend über HTTPS ansprechen.",
};

fn klartext(api: &GatewayApi, uri: &str, evidence: Evidence) -> Finding {
    befund(
        api,
        &KLARTEXT,
        format!(
            "Das Gateway leitet an {uri} weiter. Die Verbindung endet damit \
             am Gateway; im internen Netz laufen die Daten im Klartext."
        ),
        evidence,
    )
}

/// Hinter dem Gateway geht es unverschlüsselt weiter.
///
/// Maßgeblich ist das Ziel der Routing-Policy, nicht `nativeEndpoint` (die
/// Server der importierten Spec). Nur ohne jede Routing-Policy dient
/// `nativeEndpoint` als Ersatz; bei anderem Routing als
/// `straightThroughRouting` schweigt die Regel.
fn klartext_backend(api: &GatewayApi) -> Vec<Finding> {
    if api.hat_routing() {
        return api
            .routing_ziele()
            .into_iter()
            .filter(|(_, _, aufgeloest)| aufgeloest.to_lowercase().starts_with("http://"))
            .map(|(a, konfiguriert, aufgeloest)| {
                let uri = ohne_zugangsdaten(&aufgeloest);
                let note = if konfiguriert == aufgeloest {
                    String::new()
                } else {
                    format!("über Alias aufgelöst: {uri}")
                };
                let evidence = Evidence {
                    pointer: zeiger(api, a),
                    excerpt: format!("endpointUri: {}", ohne_zugangsdaten(&konfiguriert)),
                    note,
                };
                klartext(api, &uri, evidence)
            })
            .collect();
    }
    api.native_endpoints
        .iter()
        .filter(|ep| ep.is_plaintext())
        .map(|ep| {
            let uri = ohne_zugangsdaten(&ep.uri);
            let evidence = beleg(api.source_path.clone(), format!("nativeEndpoint: {uri}"));
            klartext(api, &uri, evidence)
        })
        .collect()
}

const HEADER: Vorlage = Vorlage {
    check_id: "gw.pass_security_headers",
    title: "Security-Header werden an das Backend durchgereicht",
    confidence: Confidence::Wahrscheinlich,
    severity: Severity::Medium,
    owasp: Owasp::Api8,
    remediation: "Prüfen, ob das Backend die durchgereichten Header auswertet. Wenn \
                  nicht benötigt, passSecurityHeaders abschalten.",
};

/// `passSecurityHeaders` reicht Zugangsdaten ans Backend weiter.
fn security_header_durchgereicht(api: &GatewayApi) -> Vec<Finding> {
    api.native_endpoints
        .iter()
        .filter(|ep| ep.pass_security_headers)
        .map(|ep| {
            befund(
                api,
                &HEADER,
                "Authorization- und weitere Security-Header des Aufrufers gehen \
                 unverändert an das Backend. Vertraut das Backend ihnen, entscheidet \
                 am Ende der Aufrufer über seine eigene Berechtigung."
                    .to_owned(),
                beleg(
                    api.source_path.clone(),
                    format!("passSecurityHeaders: true ({})", ohne_zugangsdaten(&ep.uri)),
                ),
            )
        })
        .collect()
}

// ------------------------------------------------------- Betrieb und Daten

const KEIN_LIMIT: Vorlage = Vorlage {
    check_id: "gw.no_traffic_limit",
    title: "Keine Begrenzung von Anfragemenge oder Nachrichtengröße",
    confidence: Confidence::Wahrscheinlich,
    severity: Severity::Medium,
    owasp: Owasp::Api4,
    remediation: "Eine Traffic-Monitoring-Policy je API setzen oder die globale \
                  Threat-Protection-Konfiguration mit exportieren und prüfen.",
};

/// Ohne Größen- und Mengenbegrenzung ist die API leicht überlastbar.
fn fehlende_threat_protection(api: &GatewayApi) -> Vec<Finding> {
    // throttle: templateKey von „Traffic Optimization“ im offiziellen IBM-Repo;
    // die übrigen Schlüssel bleiben aus Kompatibilität mit älteren Fixtures.
    if [
        "throttle",
        "throttlingPolicy",
        "trafficOptimizationPolicy",
        "requestSizeLimit",
    ]
    .iter()
    .any(|k| api.has_action(k))
    {
        return Vec::new();
    }
    vec![befund(
        api,
        &KEIN_LIMIT,
        "Auf API-Ebene ist keine Traffic-Begrenzung konfiguriert. Eine global \
         gesetzte Threat-Protection kann greifen — sie ist in diesem Export \
         jedoch nicht enthalten und daher hier nicht nachweisbar."
            .to_owned(),
        beleg(
            api.source_path.clone(),
            "keine Traffic-Optimization-Policy (throttle)".to_owned(),
        ),
    )]
}

/// Ab dieser Zählperiode (ein Tag) bremst ein Kontingent keine Lastspitzen.
const LANGES_FENSTER: u64 = 86_400;

const LANGES_KONTINGENT: Vorlage = Vorlage {
    check_id: "gw.throttle_long_window",
    title: "Lange Zählperiode: das Kontingent bremst keine Lastspitzen",
    confidence: Confidence::Wahrscheinlich,
    severity: Severity::Low,
    owasp: Owasp::Api4,
    remediation: "Prüfen, ob das Backend eine solche Spitze verkraftet. Wenn nicht: \
                  zusätzlich eine Grenze mit kurzem Intervall (etwa je Minute) oder den \
                  Bulkhead setzen. Der Lastrechner im HTML-Bericht zeigt die Wirkung.",
};

/// Ein Tages- oder Wochenkontingent lässt Spitzen ungebremst durch.
///
/// Laut IBM-Dokumentation zählt das Gateway nach dem Token-Bucket-Verfahren und
/// füllt das Kontingent erst nach Ablauf des Intervalls wieder auf. Hat dieselbe
/// API auch eine lesbare Grenze mit kürzerem Intervall, schweigt die Regel.
fn langes_kontingent(api: &GatewayApi) -> Vec<Finding> {
    let grenzen: Vec<_> = api
        .actions("throttle")
        .into_iter()
        .map(|a| (a, lastgrenze(a)))
        .filter_map(|(a, g)| match (g.limit, g.fenster_sekunden()) {
            (Some(limit), Some(fenster)) => Some((a, g, limit, fenster)),
            _ => None,
        })
        .collect();
    if grenzen
        .iter()
        .any(|(_, _, _, fenster)| *fenster < LANGES_FENSTER)
    {
        return Vec::new();
    }
    grenzen
        .into_iter()
        .map(|(a, g, limit, _)| {
            let einheit = g.einheit.as_deref().unwrap_or_default();
            let intervall = g.intervall.unwrap_or_default();
            befund(
                api,
                &LANGES_KONTINGENT,
                format!(
                    "Die Traffic-Optimization-Policy erlaubt {}. \
                     Laut IBM-Dokumentation zählt das Gateway nach dem Token-Bucket-Verfahren \
                     und füllt das Kontingent erst nach Ablauf des Intervalls wieder auf. \
                     Innerhalb des Intervalls dürfen alle Aufrufe auch in wenigen Minuten \
                     eintreffen. Gleichzeitige Aufrufe begrenzt der Bulkhead — ob er gesetzt \
                     ist, zeigt dieser Export nicht.",
                    beschreibung(g.limit, g.intervall, g.einheit.as_deref())
                ),
                beleg(
                    zeiger(api, a),
                    format!(
                        "throttleRule value: {limit}, alertInterval: {intervall}, \
                         alertIntervalUnit: {einheit}"
                    ),
                ),
            )
        })
        .collect()
}

const LOG: Vorlage = Vorlage {
    check_id: "gw.log_invocation",
    title: "Log-Invocation-Policy aktiv",
    confidence: Confidence::Wahrscheinlich,
    severity: Severity::Low,
    owasp: Owasp::Api8,
    remediation: "Prüfen, welche Bestandteile protokolliert werden, und Nutzdaten nur \
                  mit dokumentiertem Zweck und Löschfrist aufzeichnen.",
};

/// Mitgeschriebene Nutzdaten sind ein Datenschutzthema.
fn log_invocation(api: &GatewayApi) -> Vec<Finding> {
    api.actions("logInvocation")
        .into_iter()
        .map(|a| {
            befund(
                api,
                &LOG,
                "Anfragen werden protokolliert. Sind Nutzdaten eingeschlossen, landen \
                 personenbezogene Daten und Zugangsdaten in den Logs."
                    .to_owned(),
                beleg(zeiger(api, a), "logInvocation".to_owned()),
            )
        })
        .collect()
}

// ------------------------------------------------------------ Laufzeitgrenze

/// Eine Prüfung, die statisch prinzipiell nicht entscheidbar ist.
#[derive(Debug, Clone, Copy)]
pub struct RuntimeGap {
    pub key: &'static str,
    pub title: &'static str,
    pub owasp: Owasp,
    pub why: &'static str,
}

/// Was auch die Konfiguration nicht beantwortet. Wird gezählt und benannt,
/// niemals bewertet — die ehrliche Kehrseite jeder statischen Analyse.
pub const LAUFZEIT_LUECKEN: [RuntimeGap; 8] = [
    RuntimeGap {
        key: "key_verification",
        title: "Wird ein erfundener API-Key tatsächlich abgewiesen?",
        owasp: Owasp::Api2,
        why: "Ob die Policy im Betrieb greift, zeigt erst eine Anfrage.",
    },
    RuntimeGap {
        key: "jwt_signature",
        title: "Wird die JWT-Signatur wirklich geprüft?",
        owasp: Owasp::Api2,
        why: "Die Konfiguration nennt das Verfahren, nicht dessen Umsetzung.",
    },
    RuntimeGap {
        key: "object_authorization",
        title: "Erreicht ein Aufrufer fremde Objekte?",
        owasp: Owasp::Api1,
        why: "Objektbezogene Berechtigung liegt im Backend und braucht zwei Identitäten.",
    },
    RuntimeGap {
        key: "role_enforcement",
        title: "Wird die Rollenprüfung durchgesetzt?",
        owasp: Owasp::Api5,
        why: "Das Gateway identifiziert; autorisieren muss das Backend.",
    },
    RuntimeGap {
        key: "trust_header",
        title: "Lässt sich ein Trust-Header fälschen?",
        owasp: Owasp::Api2,
        why: "Hängt davon ab, wie das Backend eingehende Header behandelt.",
    },
    RuntimeGap {
        key: "global_threat_protection",
        title: "Greift eine globale Threat-Protection?",
        owasp: Owasp::Api4,
        why: "Globale Konfiguration liegt außerhalb des API-Exports.",
    },
    RuntimeGap {
        key: "security_headers",
        title: "Werden Security-Header in Antworten gesetzt?",
        owasp: Owasp::Api8,
        why: "Antwort-Header stehen in keiner Konfigurationsdatei.",
    },
    RuntimeGap {
        key: "cors",
        title: "Wie verhält sich CORS tatsächlich?",
        owasp: Owasp::Api8,
        why: "Erst eine Preflight-Anfrage zeigt die wirksame Regel.",
    },
];

// ----------------------------------------------------------------- Ausführung

/// Wendet alle Regeln an und fasst allgegenwärtige Befunde zusammen.
///
/// Der Anteil bezieht sich auf eindeutige APIs (nach Name und Version), nicht
/// auf gelesene Dateien — dieselbe API aus `test/` und `prod/` zählt einmal.
pub fn run_rules(export: &GatewayExport) -> Vec<Finding> {
    let roh: Vec<Finding> = export
        .apis
        .iter()
        .flat_map(|api| REGELN.iter().flat_map(move |regel| regel(api)))
        .collect();
    let gesamt = export
        .apis
        .iter()
        .map(GatewayApi::label)
        .collect::<HashSet<_>>()
        .len();
    aggregate(roh, gesamt)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zugangsdaten_werden_geschwaerzt() {
        for (uri, soll) in [
            ("http://u:p@h/x", "http://***@h/x"),
            ("http://h/x@y", "http://h/x@y"),
            ("http://a@b@h?q=@", "http://***@h?q=@"),
            ("ftp://h", "ftp://h"),
            ("kein uri @", "kein uri @"),
            ("HTTP://U@H", "HTTP://***@H"),
        ] {
            assert_eq!(ohne_zugangsdaten(uri), soll);
        }
    }
}
