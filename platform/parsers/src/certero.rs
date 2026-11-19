//! Native parser for CERTERO personal/labour dossier exports — the
//! `Datos de contexto del fraude` tables that accompany an Argentine
//! fraud case file.
//!
//! Tab-separated, one **person** per row, keyed by CUIL:
//!
//! ```text
//! CUIL         NOMBRE                  DOMICILIO                                  SITUACION LABORAL      FECHA DE NACIMIENTO   (sin nombre)
//! 20000000021  PERSONA EJEMPLO SIETE   CALLE UNO 885, LOCALIDAD UNO, BUENOS AIRES   Sin registro           2001-01-01
//! 20000000022  Persona Ejemplo Ocho    CALLE DOS 2090, LOCALIDAD DOS, BUENOS AIRES     EMPLEADOR EJEMPLO SA   1980-01-01            ELABORACION DE PRODUCTOS DE PANADERIA N.C.P.
//! ```
//!
//! (Shown space-aligned for legibility; the real separator is a single
//! tab, and the header ends with one.)
//!
//! The header carries a trailing tab, so there is an unnamed sixth
//! column: the AFIP activity description, populated only when the row
//! names a real employer.
//!
//! # Why this can't ride the generic CSV path
//!
//! `CsvParser` auto-detects the tab delimiter, so the *rows* parse — but
//! `GenericParser::parse_event` is a rule table over **canonical** field
//! names, and `canonical_field_exact` is an English SIEM vocabulary
//! (`user`, `srcip`, `devicename`). `CUIL`, `NOMBRE`, `DOMICILIO` all
//! resolve to `_unknown` → `Skip`, every pairwise rule sees `None`, and
//! the file ingests as **zero entities and zero relations** — silently,
//! with no parse error. Hence a native parser.
//!
//! # Node identity is the whole point
//!
//! `Person` nodes are keyed by the bare 11-digit CUIL, with **no
//! prefix**, because [`crate::bind_psp`] keys its `Person` nodes by the
//! bare 11-digit CUIT from the same case's PSP logs. Argentine CUIL and
//! CUIT share one number space, so the dossier row and the transfer
//! counterparty collapse onto one graph node. That merge is the reason
//! to ingest this file at all: in the case this parser was written for,
//! all 19 dossier CUILs appear in the PSP log, every one of them as a
//! transfer *destination*.
//!
//! Keep the id scheme in sync with `bind_psp::person` or the two
//! datasets silently stop joining.
//!
//! # Address granularity
//!
//! A full address string is too brittle to cluster on (spacing, casing,
//! apartment suffixes all differ), so addresses are emitted at two
//! levels: `Person -[Reside]-> Domicilio(full)` and
//! `Domicilio -[EnLocalidad]-> Localidad("LOCALIDAD, PROVINCIA")`. Two
//! mules at literally the same door share the `Domicilio`; two mules in
//! the same barrio share only the `Localidad`. The last comma-separated
//! component is the province and the second-to-last the locality — the
//! street part can itself contain commas, so the split is from the right.
//!
//! # Time
//!
//! A dossier row is a **standing fact**, not an event: there is no
//! observation timestamp in the file. Every relation is emitted at
//! `timestamp = 0` and carries `atemporal = "true"`. Downstream temporal
//! matching therefore treats these edges as preceding all telemetry,
//! which is the correct reading (the person's address predates the
//! fraud), but any report that quotes an edge time must check the flag
//! rather than print 1970.

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};

/// Header cells that must all be present for a file to be a CERTERO
/// dossier. Matched case-insensitively against the first non-blank line.
const REQUIRED_HEADERS: &[&str] = &["NOMBRE", "DOMICILIO"];

/// Detects a CERTERO dossier: the first non-blank line is a tab-separated
/// header whose first cell is `CUIL` or `CUIT` and which also carries
/// `NOMBRE` and `DOMICILIO`.
///
/// Deliberately keyed on the header rather than on row shape — a bare
/// "11 digits then a name" heuristic would swallow any Argentine table.
pub fn looks_like_certero(contents: &str) -> bool {
    let Some(header) = contents.lines().find(|l| !l.trim().is_empty()) else {
        return false;
    };
    if !header.contains('\t') {
        return false;
    }
    let cells: Vec<String> = header
        .split('\t')
        .map(|c| c.trim().to_uppercase())
        .collect();
    let keyed_by_id = cells
        .first()
        .is_some_and(|c| c == "CUIL" || c == "CUIT" || c == "CUIL/CUIT");
    keyed_by_id
        && REQUIRED_HEADERS
            .iter()
            .all(|want| cells.iter().any(|c| c == want))
}

/// How a `SITUACION LABORAL` cell should be read. The column mixes three
/// different kinds of value, and collapsing them would be wrong in a way
/// that matters: turning `Sin registro` into an employer node would make
/// it a hub joining every unregistered person, which then distorts the
/// centrality and anomaly scores the engine ranks on.
#[derive(Debug, PartialEq, Eq)]
enum Situacion<'a> {
    /// No registered employment. Recorded as person metadata only — no
    /// node, deliberately (see above).
    SinRegistro,
    /// A tax regime, not an employer (`MONOTRIBUTO`, `AUTONOMO`, …).
    Regimen(&'a str),
    /// A real employer: a company or, as here, a natural person.
    Empleador(&'a str),
}

/// Argentine tax/benefit regimes that can appear in `SITUACION LABORAL`
/// in place of an employer name.
///
/// **Domain list — extend as the corpus demands.** Anything not matched
/// here and not "sin registro" is treated as an employer name, so a
/// missing regime shows up as a spurious `Empleador` node rather than as
/// lost data. Compared uppercased, after whitespace collapse.
const REGIMENES: &[&str] = &[
    "MONOTRIBUTO",
    "MONOTRIBUTO SOCIAL",
    "AUTONOMO",
    "AUTÓNOMO",
    "JUBILADO",
    "PENSIONADO",
    "SERVICIO DOMESTICO",
    "SERVICIO DOMÉSTICO",
    "DESEMPLEADO",
];

fn classify_situacion(raw: &str) -> Option<Situacion<'_>> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let upper = squash(trimmed).to_uppercase();
    if upper == "SIN REGISTRO" || upper == "S/D" || upper == "-" {
        return Some(Situacion::SinRegistro);
    }
    if REGIMENES.contains(&upper.as_str()) {
        return Some(Situacion::Regimen(trimmed));
    }
    Some(Situacion::Empleador(trimmed))
}

/// Collapses runs of whitespace to single spaces and trims. Dossier cells
/// carry stray double spaces and trailing blanks (`"LOCALIDAD CUATRO "`)
/// that would otherwise fork a node in two.
fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Normalizes an identifier to its digits. CUILs appear with and without
/// hyphens (`20-00000002-1`).
fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

/// Splits an address into `(full, locality_and_province)`.
///
/// The street part can itself contain commas
/// (`"CALLE CINCO 1639 BARRIO EJEMPLO, LOCALIDAD CINCO, BUENOS AIRES"`),
/// so the province and locality are taken from the **right**. Returns
/// `None` for the locality when the address has fewer than two components.
fn split_address(raw: &str) -> Option<(String, Option<String>)> {
    // Normalize *around* the commas, not just within the string: the
    // corpus carries `"LOCALIDAD CUATRO , BUENOS AIRES"`, and keeping that
    // stray space would fork the node away from the identical address
    // written without it. Rebuilding from trimmed components also drops
    // empty segments from trailing or doubled commas.
    let parts: Vec<String> = squash(raw)
        .to_uppercase()
        .split(',')
        .map(squash)
        .filter(|p| !p.is_empty())
        .collect();
    if parts.is_empty() {
        return None;
    }
    let full = parts.join(", ");
    // The street part can itself contain commas, so locality and province
    // are the last two components.
    let locality = (parts.len() >= 2).then(|| parts[parts.len() - 2..].join(", "));
    // Entity identity is the id alone (`Entity: PartialEq` compares only
    // `id`), so a two-component address — where the locality string equals
    // the whole address — would emit a self-loop rather than a hierarchy.
    let locality = locality.filter(|l| *l != full);
    Some((full, locality))
}

/// Parses `YYYY-MM-DD` into epoch seconds. Used for metadata only — it is
/// never an edge timestamp (see module docs on atemporality).
fn birth_epoch(raw: &str) -> Option<i64> {
    chrono::NaiveDate::parse_from_str(raw.trim(), "%Y-%m-%d")
        .ok()?
        .and_hms_opt(0, 0, 0)
        .map(|dt| dt.and_utc().timestamp())
}

/// Builds the shared-identity `Person` node. Must stay byte-compatible
/// with `bind_psp::person` — see module docs.
fn person(cuil: &str) -> Entity {
    Entity::new(cuil, EntityType::Other("Person".into()))
}

fn other(id: impl Into<String>, ty: &str) -> Entity {
    Entity::new(id, EntityType::Other(ty.into()))
}

/// Emits an atemporal dossier edge (`timestamp = 0`, `atemporal = true`).
fn fact(src: &Entity, dst: &Entity, rel: &str) -> Relation {
    Relation::new(&src.id, &dst.id, RelationType::Other(rel.into()), 0)
        .with_metadata("atemporal", "true")
        .with_metadata("fuente", "certero")
}

pub struct CerteroParser;

/// Column indices resolved from the header, so a reordered export still
/// parses. `actividad` is the unnamed trailing column.
struct Columns {
    cuil: usize,
    nombre: Option<usize>,
    domicilio: Option<usize>,
    situacion: Option<usize>,
    nacimiento: Option<usize>,
    actividad: Option<usize>,
}

impl Columns {
    fn from_header(header: &str) -> Self {
        let cells: Vec<String> = header
            .split('\t')
            .map(|c| squash(c).to_uppercase())
            .collect();
        let find = |want: &str| cells.iter().position(|c| c == want);
        // The activity column has no header name; it is the first blank
        // header cell after the named ones.
        let actividad = cells
            .iter()
            .enumerate()
            .find(|(i, c)| c.is_empty() && *i > 0)
            .map(|(i, _)| i);
        Self {
            cuil: 0,
            nombre: find("NOMBRE"),
            domicilio: find("DOMICILIO"),
            situacion: find("SITUACION LABORAL").or_else(|| find("SITUACIÓN LABORAL")),
            nacimiento: find("FECHA DE NACIMIENTO").or_else(|| find("FECHA NACIMIENTO")),
            actividad,
        }
    }
}

fn cell<'a>(row: &'a [&'a str], idx: Option<usize>) -> &'a str {
    idx.and_then(|i| row.get(i)).map_or("", |s| s.trim())
}

impl CerteroParser {
    fn parse_inner(&self, data: &str) -> Vec<ParsedTriple> {
        let mut lines = data.lines().filter(|l| !l.trim().is_empty());
        let Some(header) = lines.next() else {
            return Vec::new();
        };
        let cols = Columns::from_header(header);
        let mut triples = Vec::new();

        for line in lines {
            let row: Vec<&str> = line.split('\t').collect();
            let cuil = digits(row.get(cols.cuil).unwrap_or(&""));
            // CUIL/CUIT is always 11 digits; anything else is a stray row.
            if cuil.len() != 11 {
                continue;
            }

            let nombre = squash(cell(&row, cols.nombre));
            let nacimiento = cell(&row, cols.nacimiento);
            let situacion_raw = cell(&row, cols.situacion);
            let actividad = squash(cell(&row, cols.actividad));

            let mut p = person(&cuil).with_metadata("fuente", "certero");
            if !nombre.is_empty() {
                p = p.with_metadata("nombre", &nombre);
            }
            if !nacimiento.is_empty() {
                p = p.with_metadata("fecha_nacimiento", nacimiento);
                if let Some(epoch) = birth_epoch(nacimiento) {
                    p = p.with_metadata("fecha_nacimiento_epoch", epoch.to_string());
                }
            }
            if !situacion_raw.is_empty() {
                p = p.with_metadata("situacion_laboral", squash(situacion_raw));
            }
            if !actividad.is_empty() {
                p = p.with_metadata("actividad_afip", &actividad);
            }
            // The absence of registered work is itself the signal in a
            // mule roster, so it stays queryable as a flag rather than
            // becoming a hub node.
            if matches!(
                classify_situacion(situacion_raw),
                Some(Situacion::SinRegistro)
            ) {
                p = p.with_metadata("sin_registro_laboral", "true");
            }

            let emitted_before = triples.len();

            if let Some((full, locality)) = split_address(cell(&row, cols.domicilio)) {
                let dom = other(&full, "Domicilio");
                triples.push((p.clone(), fact(&p, &dom, "Reside"), dom.clone()));
                if let Some(loc) = locality {
                    let l = other(&loc, "Localidad");
                    triples.push((dom.clone(), fact(&dom, &l, "EnLocalidad"), l));
                }
            }

            match classify_situacion(situacion_raw) {
                Some(Situacion::Empleador(name)) => {
                    let e = other(squash(name).to_uppercase(), "Empleador");
                    triples.push((p.clone(), fact(&p, &e, "Empleado"), e));
                }
                Some(Situacion::Regimen(name)) => {
                    let r = other(squash(name).to_uppercase(), "RegimenFiscal");
                    triples.push((p.clone(), fact(&p, &r, "Regimen"), r));
                }
                Some(Situacion::SinRegistro) | None => {}
            }

            if !actividad.is_empty() {
                let a = other(actividad.to_uppercase(), "Actividad");
                triples.push((p.clone(), fact(&p, &a, "Actividad"), a));
            }

            // A person with no address, employer or activity would emit
            // nothing at all and vanish from the graph. Anchor them to
            // the dataset so the roster stays complete and countable.
            // Compared against this row's own starting offset — scanning
            // the accumulated vec instead would make the parse quadratic
            // in the row count.
            if triples.len() == emitted_before {
                let roster = other("CERTERO", "Dataset");
                triples.push((p.clone(), fact(&p, &roster, "Listado"), roster));
            }
        }
        triples
    }
}

impl LogParser for CerteroParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        self.parse_inner(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Rows with the exact shape of the case corpus, synthetic values
    /// throughout (the trailing tab on the header
    /// and on the unemployed rows is load-bearing — it is the unnamed
    /// activity column).
    const SAMPLE: &str = "CUIL\tNOMBRE\tDOMICILIO\tSITUACION LABORAL\tFECHA DE NACIMIENTO\t
20000000021\tPERSONA EJEMPLO SIETE\tCALLE UNO 885, LOCALIDAD UNO, BUENOS AIRES\tSin registro\t2001-01-01\t
20000000022\tPersona Ejemplo Ocho\tCALLE DOS 2090, LOCALIDAD DOS, BUENOS AIRES\tEMPLEADOR EJEMPLO SA\t1980-01-01\tELABORACIÓN DE PRODUCTOS DE PANADERÍA N.C.P.
20000000023\tPERSONA EJEMPLO NUEVE\tCALLE TRES 2237 BARRIO EJEMPLO DOS, LOCALIDAD TRES, BUENOS AIRES\tMONOTRIBUTO\t1981-01-01\t
23000000024\tPersona Ejemplo Diez\tCALLE CUATRO 2039 DPTO/CASA:4, LOCALIDAD CUATRO , BUENOS AIRES\tSin registro\t2002-01-01\t
";

    fn edges(data: &str) -> Vec<(String, String, String)> {
        CerteroParser
            .parse(data)
            .into_iter()
            .map(|(s, r, d)| (s.id, r.rel_type.to_string(), d.id))
            .collect()
    }

    #[test]
    fn detects_the_format_and_rejects_others() {
        assert!(looks_like_certero(SAMPLE));
        // Right shape, wrong key column.
        assert!(!looks_like_certero("ID\tNOMBRE\tDOMICILIO\n1\ta\tb\n"));
        // Comma-separated, not tabs.
        assert!(!looks_like_certero("CUIL,NOMBRE,DOMICILIO\n1,a,b\n"));
        assert!(!looks_like_certero(
            "{\"MSec\":\"1\",\"EventName\":\"x\"}\n"
        ));
        assert!(!looks_like_certero(""));
    }

    /// The identity contract with `bind_psp`: a `Person` node is the bare
    /// 11-digit number, unprefixed, so a dossier row and a PSP transfer
    /// counterparty land on the same node. Breaking this silently
    /// un-joins the two datasets.
    #[test]
    fn person_nodes_are_the_bare_cuil() {
        let t = CerteroParser.parse(SAMPLE);
        let p = &t[0].0;
        assert_eq!(p.id, "20000000021");
        assert_eq!(p.entity_type, EntityType::Other("Person".into()));
        // Hyphenated CUILs normalize to the same node.
        let hyphenated = SAMPLE.replace("20000000021", "20-00000002-1");
        assert_eq!(CerteroParser.parse(&hyphenated)[0].0.id, "20000000021");
    }

    #[test]
    fn address_splits_into_domicilio_and_localidad() {
        let e = edges(SAMPLE);
        assert!(e.contains(&(
            "20000000021".into(),
            "Reside".into(),
            "CALLE UNO 885, LOCALIDAD UNO, BUENOS AIRES".into()
        )));
        assert!(e.contains(&(
            "CALLE UNO 885, LOCALIDAD UNO, BUENOS AIRES".into(),
            "EnLocalidad".into(),
            "LOCALIDAD UNO, BUENOS AIRES".into()
        )));
    }

    /// A street part containing its own comma must not steal the locality
    /// slot — the split is from the right.
    #[test]
    fn street_commas_do_not_shift_the_locality() {
        let row = "CUIL\tNOMBRE\tDOMICILIO\tSITUACION LABORAL\tFECHA DE NACIMIENTO\t
20000000025\tPERSONA EJEMPLO ONCE\tCALLE CINCO 1639 BARRIO EJEMPLO, LOCALIDAD CINCO, BUENOS AIRES\tSin registro\t1999-01-01\t
";
        assert!(edges(row).contains(&(
            "CALLE CINCO 1639 BARRIO EJEMPLO, LOCALIDAD CINCO, BUENOS AIRES".into(),
            "EnLocalidad".into(),
            "LOCALIDAD CINCO, BUENOS AIRES".into()
        )));
    }

    /// Trailing/double spaces must not fork a locality node in two.
    #[test]
    fn whitespace_is_squashed_before_keying() {
        assert!(edges(SAMPLE).contains(&(
            "CALLE CUATRO 2039 DPTO/CASA:4, LOCALIDAD CUATRO, BUENOS AIRES".into(),
            "EnLocalidad".into(),
            "LOCALIDAD CUATRO, BUENOS AIRES".into()
        )));
    }

    /// The three kinds of `SITUACION LABORAL` value must not collapse:
    /// an employer becomes a node, a tax regime becomes a *different*
    /// kind of node, and "Sin registro" becomes neither.
    #[test]
    fn situacion_laboral_splits_three_ways() {
        let t = CerteroParser.parse(SAMPLE);
        let e: Vec<(String, String, String)> = t
            .iter()
            .map(|(s, r, d)| (s.id.clone(), r.rel_type.to_string(), d.id.clone()))
            .collect();

        assert!(e.contains(&(
            "20000000022".into(),
            "Empleado".into(),
            "EMPLEADOR EJEMPLO SA".into()
        )));
        assert!(e.contains(&("20000000023".into(), "Regimen".into(), "MONOTRIBUTO".into())));
        // "Sin registro" must never become a node — it would hub every
        // unregistered person together and skew centrality.
        assert!(
            !e.iter()
                .any(|(_, _, d)| d.eq_ignore_ascii_case("SIN REGISTRO")),
            "Sin registro leaked into a node: {e:?}"
        );
        // …but it stays queryable as a flag.
        let santos = t.iter().find(|(s, _, _)| s.id == "20000000021").unwrap();
        assert_eq!(santos.0.metadata["sin_registro_laboral"], "true");
        assert_eq!(santos.0.metadata["situacion_laboral"], "Sin registro");
    }

    #[test]
    fn afip_activity_becomes_its_own_node() {
        assert!(edges(SAMPLE).contains(&(
            "20000000022".into(),
            "Actividad".into(),
            "ELABORACIÓN DE PRODUCTOS DE PANADERÍA N.C.P.".into()
        )));
    }

    #[test]
    fn person_metadata_carries_the_dossier() {
        let t = CerteroParser.parse(SAMPLE);
        let p = &t.iter().find(|(s, _, _)| s.id == "20000000022").unwrap().0;
        assert_eq!(p.metadata["nombre"], "Persona Ejemplo Ocho");
        assert_eq!(p.metadata["fecha_nacimiento"], "1980-01-01");
        assert_eq!(p.metadata["situacion_laboral"], "EMPLEADOR EJEMPLO SA");
        assert_eq!(p.metadata["fuente"], "certero");
        // 1980-01-01T00:00:00Z
        assert_eq!(p.metadata["fecha_nacimiento_epoch"], "315532800");
    }

    /// Dossier rows are standing facts, not observations.
    #[test]
    fn edges_are_atemporal() {
        for (_, rel, _) in CerteroParser.parse(SAMPLE) {
            assert_eq!(rel.timestamp, 0);
            assert_eq!(rel.metadata["atemporal"], "true");
        }
    }

    /// A row with nothing but a CUIL still has to appear in the graph —
    /// the roster is evidence even when the columns are blank.
    #[test]
    fn a_bare_row_still_anchors_to_the_dataset() {
        let sparse = "CUIL\tNOMBRE\tDOMICILIO\tSITUACION LABORAL\tFECHA DE NACIMIENTO\t
20000000026\t\t\t\t\t
";
        assert_eq!(
            edges(sparse),
            vec![("20000000026".into(), "Listado".into(), "CERTERO".into())]
        );
    }

    #[test]
    fn malformed_rows_are_skipped_not_fatal() {
        let bad = "CUIL\tNOMBRE\tDOMICILIO\tSITUACION LABORAL\tFECHA DE NACIMIENTO\t
not-a-cuil\tX\tY, Z\tSin registro\t2000-01-01\t
123\tShort\tY, Z\tSin registro\t2000-01-01\t
20000000021\tOK\tCALLE 1, LOCALIDAD, PROVINCIA\tSin registro\t2001-01-01\t
";
        let t = CerteroParser.parse(bad);
        assert!(
            t.iter()
                .all(|(s, _, _)| s.id == "20000000021" || s.id == "CALLE 1, LOCALIDAD, PROVINCIA")
        );
        assert!(!t.is_empty());
    }

    #[test]
    fn empty_and_header_only_input_is_safe() {
        assert!(CerteroParser.parse("").is_empty());
        assert!(
            CerteroParser
                .parse("CUIL\tNOMBRE\tDOMICILIO\tSITUACION LABORAL\tFECHA DE NACIMIENTO\t\n")
                .is_empty()
        );
    }
}
