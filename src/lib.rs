//! wm-audit — statische Security-Analyse für webMethods-API-Gateway-Exporte.
//!
//! Zweite, unabhängige Implementierung neben einer Referenzimplementierung. Beide Implementierungen
//! liefern für denselben Export byte-identische Berichte; die Golden-Files in
//! `code/wm-audit/tests/golden` sind der Vertrag zwischen beiden.
//!
//! Sicherheitseigenschaften (Details in `SICHERHEIT.md`):
//!
//! * kein `unsafe` (per Lint verboten), keine Netzwerkfunktionen, kein C-Code;
//! * geschrieben wird nur die ausdrücklich angegebene Ausgabedatei;
//! * Einträge mit Zugangsdaten (`PassmanData`, `Keystore`, …) werden nie geöffnet;
//! * harte Grenzen gegen ZIP- und JSON-Bomben, Symlinks werden nicht verfolgt.

pub mod befund;
pub mod bericht;
pub mod lesen;
pub mod modell;
pub mod regeln;
pub mod werte;

/// Version des Werkzeugs.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
