//! Befund-Modell und Aggregation.

use std::collections::{HashMap, HashSet};

use sha1::{Digest, Sha1};

/// Wie belastbar ist die Aussage?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confidence {
    /// Direkt aus dem Export ablesbar. Fließt in die Bewertung ein.
    Belegt,
    /// Starkes Indiz, aber nicht abschließend entscheidbar. Hinweis, kein Urteil.
    Wahrscheinlich,
}

impl Confidence {
    pub fn code(self) -> &'static str {
        match self {
            Confidence::Belegt => "belegt",
            Confidence::Wahrscheinlich => "wahrscheinlich",
        }
    }
}

/// Schwere; die Reihenfolge ist die Rangfolge (am schwersten zuerst).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl Severity {
    pub const ALLE: [Severity; 5] = [
        Severity::Critical,
        Severity::High,
        Severity::Medium,
        Severity::Low,
        Severity::Info,
    ];

    pub fn code(self) -> &'static str {
        match self {
            Severity::Critical => "critical",
            Severity::High => "high",
            Severity::Medium => "medium",
            Severity::Low => "low",
            Severity::Info => "info",
        }
    }

    pub fn aus_code(code: &str) -> Option<Severity> {
        Severity::ALLE.into_iter().find(|s| s.code() == code)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Owasp {
    Api1,
    Api2,
    Api4,
    Api5,
    Api8,
}

impl Owasp {
    pub fn code(self) -> &'static str {
        match self {
            Owasp::Api1 => "API1",
            Owasp::Api2 => "API2",
            Owasp::Api4 => "API4",
            Owasp::Api5 => "API5",
            Owasp::Api8 => "API8",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Dokument,
    Api,
}

impl Scope {
    pub fn code(self) -> &'static str {
        match self {
            Scope::Dokument => "dokument",
            Scope::Api => "api",
        }
    }
}

/// Der Beleg im Export — ohne ihn ist ein Befund eine Behauptung.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub pointer: String,
    pub excerpt: String,
    pub note: String,
}

/// Ein statischer Befund. `method`, `dimension` und `cap` des Referenz-Modells
/// sind in wm-audit immer `None`/`"design"`/`None` und werden im Bericht fest
/// ausgegeben.
#[derive(Debug, Clone)]
pub struct Finding {
    pub check_id: &'static str,
    pub title: String,
    pub confidence: Confidence,
    pub severity: Severity,
    pub owasp: Option<Owasp>,
    pub scope: Scope,
    pub subject: String,
    pub reason: String,
    pub remediation: String,
    pub evidence: Vec<Evidence>,
    pub aggregate_count: Option<usize>,
    pub affected: Vec<String>,
}

impl Finding {
    /// Stabile Kennung — gleiche Eingabe ergibt gleiche Kennung.
    pub fn id(&self) -> String {
        let roh = format!("{}||{}", self.check_id, self.subject);
        let mut hex: String = Sha1::digest(roh.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        hex.truncate(12);
        hex
    }

    /// Nur belegte Befunde wirken auf die Bewertung.
    pub fn bewertet(&self) -> bool {
        self.confidence == Confidence::Belegt
    }
}

/// Ab diesem Anteil betroffener Subjekte wird eine Regel aggregiert gemeldet.
pub const AGGREGAT_SCHWELLE: f64 = 0.5;

/// Dedupliziert, fasst allgegenwärtige Befunde zusammen und sortiert.
///
/// Eine Regel, die bei mehr als der Hälfte aller APIs anschlägt, beschreibt
/// eine Betriebsgewohnheit; sie wird einmal gemeldet statt N-mal. Ein belegter
/// Befund behält dabei seine Schwere, ein Hinweis wird zur Information.
pub fn aggregate(findings: Vec<Finding>, gesamt: usize) -> Vec<Finding> {
    let mut gesehen = HashSet::new();
    let eindeutig: Vec<Finding> = findings
        .into_iter()
        .filter(|f| gesehen.insert(f.id()))
        .collect();

    let gesamt = gesamt.max(1);
    let mut betroffen: HashMap<&'static str, Vec<String>> = HashMap::new();
    for f in &eindeutig {
        let liste = betroffen.entry(f.check_id).or_default();
        if !liste.contains(&f.subject) {
            liste.push(f.subject.clone());
        }
    }

    let mut ergebnis = Vec::new();
    let mut aggregiert = HashSet::new();
    for f in eindeutig {
        let mut liste = betroffen.get(f.check_id).cloned().unwrap_or_default();
        let n = liste.len();
        let zusammenfassen =
            f.scope != Scope::Dokument && (n as f64) / (gesamt as f64) > AGGREGAT_SCHWELLE;
        if !zusammenfassen {
            ergebnis.push(f);
            continue;
        }
        if !aggregiert.insert(f.check_id) {
            continue;
        }
        let einheit = if f.scope == Scope::Api {
            "APIs"
        } else {
            "Endpunkten"
        };
        let bleibt = f.confidence == Confidence::Belegt;
        liste.sort();
        ergebnis.push(Finding {
            scope: Scope::Dokument,
            subject: format!("{n} von {gesamt} {einheit}"),
            aggregate_count: Some(n),
            affected: liste,
            severity: if bleibt { f.severity } else { Severity::Info },
            title: format!("{} (durchgängig)", f.title),
            reason: format!(
                "Betrifft {n} von {gesamt} {einheit}. Ein Merkmal, das nahezu überall \
                 auftritt, beschreibt eine Gewohnheit und wird deshalb gesammelt gemeldet \
                 statt je Endpunkt einzeln. {}",
                f.reason
            ),
            evidence: Vec::new(),
            ..f
        });
    }

    ergebnis.sort_by(|a, b| {
        (a.severity, a.check_id, &a.subject).cmp(&(b.severity, b.check_id, &b.subject))
    });
    ergebnis
}
