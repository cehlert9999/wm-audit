//! Lesart für JSON-Werte aus einem Gateway-Export.
//!
//! Ein Export kommt aus Gateway-Versionen, die Felder unterschiedlich
//! serialisieren: ein Wahrheitswert steht mal als `true`, mal als `"true"`, eine
//! Version mal als `"1.0"`, mal als Zahl. Hier ist **eine** Lesart festgelegt,
//! damit aus einem Feld nie stillschweigend das Gegenteil wird.

use serde_json::{Map, Number, Value};

/// Ein JSON-Objekt (Schlüssel sortiert).
pub type Objekt = Map<String, Value>;

/// Text eines Skalars. Listen, Objekte und `null` ergeben `""`.
pub fn text(v: Option<&Value>) -> String {
    match v {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(true)) => "true".to_owned(),
        Some(Value::Bool(false)) => "false".to_owned(),
        Some(Value::Number(n)) => zahl(n),
        _ => String::new(),
    }
}

/// Wie [`text`], aber ein fehlendes oder `null`-Feld bleibt `None`.
pub fn text_oder_none(v: Option<&Value>) -> Option<String> {
    match v {
        None | Some(Value::Null) => None,
        w => Some(text(w)),
    }
}

fn zahl(n: &Number) -> String {
    if let Some(u) = n.as_u64() {
        u.to_string()
    } else if let Some(i) = n.as_i64() {
        i.to_string()
    } else {
        float_text(n.as_f64().unwrap_or(0.0))
    }
}

/// Liegt der exakte Wert genau in der Mitte zwischen zwei kürzesten Ziffernfolgen
/// (etwa `…602.625` zwischen `…602.62` und `…602.63`), gilt die Folge mit
/// gerader letzter Ziffer; `{:e}` rundet dann auf. Liefert in diesem Fall Ziffern
/// und Exponent dieser Wahl, sonst `None`.
fn gerade_bei_gleichstand(betrag: f64, laenge: usize) -> Option<(String, i32)> {
    // Ein f64 hat höchstens 767 signifikante Dezimalstellen: mit 800 Stellen ist
    // diese Darstellung exakt und nicht gerundet.
    let exakt = format!("{betrag:.800e}");
    let (mantisse, exponent) = exakt.split_once('e')?;
    let exponent: i32 = exponent.parse().ok()?;
    let alle: String = mantisse.chars().filter(|c| *c != '.').collect();
    let alle = alle.trim_end_matches('0');
    if alle.len() != laenge + 1 || !alle.ends_with('5') {
        return None;
    }
    let abgeschnitten = alle.get(..laenge)?;
    let gerade = abgeschnitten
        .bytes()
        .last()
        .is_some_and(|b| (b - b'0').is_multiple_of(2));
    let wahl = if gerade {
        abgeschnitten.to_owned()
    } else {
        plus_eins(abgeschnitten)?
    };
    // Nur übernehmen, wenn die Wahl beim Zurücklesen denselben Wert ergibt.
    let (erste, rest) = wahl.split_at_checked(1)?;
    let zurueck: f64 = format!("{erste}.{rest}e{exponent}").parse().ok()?;
    (zurueck == betrag).then_some((wahl, exponent))
}

/// `"129"` → `"130"`; `None`, wenn der Übertrag über alle Stellen läuft.
fn plus_eins(ziffern: &str) -> Option<String> {
    let mut stellen = ziffern.as_bytes().to_vec();
    for z in stellen.iter_mut().rev() {
        if *z == b'9' {
            *z = b'0';
        } else {
            *z += 1;
            return String::from_utf8(stellen).ok();
        }
    }
    None
}

/// Gleitkommazahl als Text: kürzeste Ziffernfolge, die zurückgelesen denselben Wert ergibt.
///
/// Beide nutzen die kürzeste Ziffernfolge, die beim Zurücklesen denselben Wert
/// ergibt; ab Exponent 16 und unter −4 wissenschaftlich (`1e+16`, `1e-05`).
pub fn float_text(f: f64) -> String {
    let wissenschaftlich = format!("{f:e}");
    let (mantisse, exponent) = wissenschaftlich
        .split_once('e')
        .unwrap_or((wissenschaftlich.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let (vorzeichen, mantisse) = match mantisse.strip_prefix('-') {
        Some(m) => ("-", m),
        None => ("", mantisse),
    };
    let ziffern: String = mantisse.chars().filter(|c| *c != '.').collect();
    let (ziffern, exponent) =
        gerade_bei_gleichstand(f.abs(), ziffern.len()).unwrap_or((ziffern, exponent));

    if (-4..16).contains(&exponent) {
        if exponent >= 0 {
            let stellen = exponent.unsigned_abs() as usize + 1;
            if ziffern.len() > stellen {
                let (ganz, bruch) = ziffern.split_at(stellen);
                format!("{vorzeichen}{ganz}.{bruch}")
            } else {
                let nullen = "0".repeat(stellen - ziffern.len());
                format!("{vorzeichen}{ziffern}{nullen}.0")
            }
        } else {
            let nullen = "0".repeat(exponent.unsigned_abs() as usize - 1);
            format!("{vorzeichen}0.{nullen}{ziffern}")
        }
    } else {
        let (erste, rest) = ziffern.split_at(ziffern.len().min(1));
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        let zeichen = if exponent < 0 { '-' } else { '+' };
        format!(
            "{vorzeichen}{erste}{rest}e{zeichen}{:02}",
            exponent.unsigned_abs()
        )
    }
}

/// `true`/`false` als JSON-Wert oder als Text (Groß-/Kleinschreibung egal).
pub fn wahrheitswert(v: Option<&Value>, standard: bool) -> bool {
    match v {
        Some(Value::Bool(b)) => *b,
        Some(Value::String(s)) => match s.to_lowercase().as_str() {
            "true" => true,
            "false" => false,
            _ => standard,
        },
        _ => standard,
    }
}

/// Nicht negative Ganzzahl aus reinem Ziffern-Text, sonst `None`.
///
/// Höchstens 18 Ziffern, damit jeder Wert in `u64` passt und in der Referenz gleich
/// gelesen wird. Vorzeichen, Leerzeichen, Dezimalpunkt oder Ziffern anderer
/// Schriften gelten als nicht lesbar.
pub fn anzahl(s: &str) -> Option<u64> {
    if s.is_empty() || s.len() > 18 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Liste → Text je Element; ein einzelner Skalar → einelementige Liste.
pub fn text_liste(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a.iter().map(|x| text(Some(x))).collect(),
        None | Some(Value::Null) | Some(Value::Object(_)) => Vec::new(),
        w => vec![text(w)],
    }
}

/// Nur die JSON-Objekte einer Liste; alles andere wird ignoriert.
pub fn objekte(v: Option<&Value>) -> Vec<&Objekt> {
    match v {
        Some(Value::Array(a)) => a.iter().filter_map(Value::as_object).collect(),
        _ => Vec::new(),
    }
}

/// `[{"value": "...", "locale": "en"}]` → erster Wert.
pub fn lokalisiert(v: Option<&Value>) -> String {
    match v {
        Some(Value::Array(a)) => match a.first() {
            Some(Value::Object(o)) => text(o.get("value")),
            _ => String::new(),
        },
        _ => String::new(),
    }
}

/// Maximale Verschachtelungstiefe von Arrays/Objekten, Strings ausgenommen.
///
/// Läuft **vor** dem Parser, damit eine Tiefenbombe nie den Rekursionsstapel
/// erreicht; arbeitet auf ungültigem JSON genauso wie die Referenz.
pub fn verschachtelung(quelle: &str) -> usize {
    let (mut tiefe, mut maximum) = (0i64, 0i64);
    let (mut im_string, mut escape) = (false, false);
    for &b in quelle.as_bytes() {
        if im_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                im_string = false;
            }
            continue;
        }
        match b {
            b'"' => im_string = true,
            b'[' | b'{' => {
                tiefe += 1;
                maximum = maximum.max(tiefe);
            }
            b']' | b'}' => tiefe -= 1,
            _ => {}
        }
    }
    usize::try_from(maximum).unwrap_or(0)
}

/// Striktes JSON: kein `NaN`/`Infinity`, nur endliche Zahlen, gültiges Unicode.
pub fn lade_json(quelle: &str) -> Option<Value> {
    serde_json::from_str(quelle).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn float_text_kuerzeste_darstellung() {
        for (f, soll) in [
            (1.0, "1.0"),
            (1.5, "1.5"),
            (100.0, "100.0"),
            (1e16, "1e+16"),
            (1.5e16, "1.5e+16"),
            (9007199254740992.0, "9007199254740992.0"),
            (1e-4, "0.0001"),
            (1e-5, "1e-05"),
            (-0.0, "-0.0"),
            (0.0, "0.0"),
            (0.1 + 0.2, "0.30000000000000004"),
            (5e-324, "5e-324"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (-1.2345678901234568e22, "-1.2345678901234568e+22"),
            (123456789.125, "123456789.125"),
        ] {
            assert_eq!(float_text(f), soll, "{f:e}");
        }
    }

    /// Gleichstände: gewählt wird die gerade letzte Ziffer. Die Tabelle stammt aus
    /// der Referenzimplementierung (Bitmuster des f64, erwarteter Text).
    #[test]
    fn float_text_gleichstand_gerade() {
        for (bits, soll) in [
            (0x431ac3556f03675b, "1883280274151894.8"),
            (0x423f44d726c86c00, "134298937032.42188"),
            (0x430c77ddb66399a6, "1001636684919604.8"),
            (0x42d6c56d5824fd28, "100148795446260.62"),
            (0x42dbd8d7dae4eab8, "122472593331114.88"),
            (0x42ef17500f877ae4, "273479903230935.12"),
            (0x430ba4afb27fee2e, "972612361518533.8"),
            (0xc30fcdb4e5dcd45e, "-1118987639036555.8"),
            (0x42b889af2a70afb0, "26979628380335.688"),
            (0x430c9b0bf8dca30a, "1006471883756641.2"),
            (0x43199f357924dedf, "1802981608077239.8"),
            (0xc2ef7acce2bce764, "-276898271061819.12"),
            (0x4318a41adc265c67, "1733958677665561.8"),
            (0x42b89164a75bb030, "27012738014128.188"),
            (0x430a012869549442, "914952808993416.2"),
            (0x43117b3a29b366d7, "1230141085505973.8"),
            (0x430f04ec7bf2a7f6, "1091392252040446.8"),
            (0x431e8ffc3bdfae69, "2150640700091290.2"),
            (0x42d2c682efd29af8, "82575238318699.88"),
            (0xc2bfb494f7d39db0, "-34860453843869.688"),
            (0xc2b6f6f7c00f4af0, "-25249974325066.938"),
            (0x43036599c1c81c2e, "682466951627653.8"),
            (0x42dc4333a850e4a8, "124299820221330.62"),
            (0x4248154f7833e200, "206873489511.76562"),
            (0x42d97b86cdca38a8, "112073333221602.62"),
        ] {
            let f = f64::from_bits(bits);
            assert_eq!(float_text(f), soll, "{f:e}");
        }
    }

    #[test]
    fn wahrheitswert_aus_text() {
        let v = |s: &str| Value::String(s.to_owned());
        assert!(!wahrheitswert(Some(&v("false")), true));
        assert!(!wahrheitswert(Some(&v("False")), true));
        assert!(wahrheitswert(Some(&v("TRUE")), false));
        assert!(!wahrheitswert(Some(&v(" true")), false));
        assert!(wahrheitswert(Some(&v("ja")), true));
        assert!(!wahrheitswert(Some(&Value::from(1)), false));
    }

    #[test]
    fn verschachtelung_ignoriert_strings() {
        assert_eq!(verschachtelung("{}"), 1);
        assert_eq!(verschachtelung(r#"{"a": [[1]]}"#), 3);
        assert_eq!(verschachtelung(r#""[[[""#), 0);
        assert_eq!(verschachtelung(r#"{"a": "\"[["}"#), 1);
        assert_eq!(verschachtelung(r#"["\\", [1]]"#), 2);
        assert_eq!(verschachtelung("]]]"), 0);
    }
}
