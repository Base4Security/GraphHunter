//! Native parser for BIND PSP connector application logs — the Spring
//! Boot service that fronts `api.bindpagos.com.ar` for an Argentine
//! wallet, consolidated as newline-delimited JSON:
//!
//! ```json
//! {"labels":{},"line":"2026-09-03 00:00:17,183 [http-nio-8080-exec-39] INFO  [sId:1945…] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [POST] [https://api.bindpagos.com.ar/…/transferir] [{…}] - time_elapsed: [584 ms] - RESPONSE: [200] [{…}]","timestamp":"2026-09-03T00:00:17.183Z"}
//! ```
//!
//! # Why this can't ride the generic JSON path
//!
//! The envelope has exactly three keys — `labels`, `line`, `timestamp` —
//! and every fact worth graphing (CVUs, CUITs, amounts, counterparties)
//! is inside `line` as an *unstructured string* that happens to embed
//! JSON. `GenericParser` sees a bag of three fields, none canonical, and
//! produces nothing useful. The payload has to be dug out of the log
//! line itself.
//!
//! # Node identity
//!
//! Identity is the id **alone** (`Entity: PartialEq` compares only `id`,
//! ignoring `entity_type`), so ids are prefixed wherever a collision is
//! possible:
//!
//! | Node        | Id                          | Notes |
//! |-------------|-----------------------------|-------|
//! | `Person`    | bare 11-digit CUIT/CUIL     | **unprefixed on purpose** — merges with [`crate::certero`] |
//! | `Account`   | 22-digit CVU/CBU            | the only id shared between "our" accounts and counterparties |
//! | `Account`   | `acct:{internalId}`         | when only the wallet's internal account id is known |
//! | `Bank`      | `bco:{code or name}`        | |
//! | `Alias`     | `alias:{alias}`             | |
//! | `Domicilio` | uppercased address          | merges with [`crate::certero`] |
//! | `Endpoint`  | `api:{name}`                | |
//!
//! The wallet's own accounts appear under **both** account ids depending
//! on the endpoint: webhooks name `cuentaId` (internal), transfers name
//! `cvu_origen`. `Cuenta/{id}` responses carry both, so they emit an
//! `acct:{id} -[MismaCuenta]-> {cvu}` bridge and traversal crosses the
//! two id spaces in one hop. There is deliberately no cross-line state:
//! the ingest pipeline streams this file as **independently parsed line
//! batches** (`is_line_based` in `platform/api/src/operations/ingestion.rs`,
//! which routes anything whose peek starts with `{` to the mmap path), so
//! a parser that remembered ids across lines would drop edges at every
//! batch boundary.
//!
//! # Every settled amount is logged three times
//!
//! Each money movement appears as (1) a `REQUEST: [POST]
//! [/webhook/newOperationNotification]` call, (2) a
//! `saveNewOperationNotification` line carrying the identical payload,
//! and — when it was the wallet initiating — (3) a `POST …/transferir`
//! call/response. In the corpus this was written against: 9.007 of (1),
//! 9.007 of (2), 4.179 successful (3).
//!
//! Summing naively inflates every total ~3×, so:
//!
//! - **`Transfer` edges come only from (2)**, the canonical settled
//!   record. Variant (1) is explicitly skipped.
//! - **(3) becomes `IntentoTransfer`**, a different relation type: an
//!   *attempt*, carrying the HTTP status. This is not double counting —
//!   it is the only place rejections are visible at all (763 `409
//!   Rechazada ARDID`, 236 `422`), which no webhook ever reports. Both
//!   sides carry `coelsa_id`, so an attempt and its settlement can be
//!   paired at query time.
//!
//! Anything summing money must therefore filter on `rel_type ==
//! "Transfer"`.
//!
//! # Direction is where the value went
//!
//! `evento` names the direction relative to the wallet's account:
//! `*_ENTRANTE` → counterparty → us, `*_SALIENTE` → us → counterparty.
//! `PAGO_QR` is treated as outgoing (the wallet holder paying a merchant);
//! `evento` is preserved on every edge so that reading can be revisited
//! without a re-ingest.
//!
//! # Time, and events vs. standing facts
//!
//! Edges divide in two, and the split matters for scoring:
//!
//! **Events** — `Transfer`, `IntentoTransfer`, `Consultado` — happened
//! between their two nodes at an instant. Their time is the **business**
//! time (`fechaCreacion` / `fechaInicio`) when the payload carries one,
//! falling back to the log envelope's `timestamp`. The log lags
//! settlement by seconds and that lag is not constant, so ordering a
//! chain of transfers by log time can transpose two hops. `ts_source`
//! records which clock was used and `ts_log_epoch` always keeps the
//! envelope value, so the choice is auditable.
//!
//! **Standing facts** — `Titular`, `Cotitular`, `MismaCuenta`,
//! `TieneAlias`, `EnBanco`, `Reside` — are attributes a lookup revealed,
//! not events. They are emitted at `timestamp = 0` with
//! `atemporal = "true"`, matching [`crate::certero`] so the same fact
//! from either dataset reads identically. See [`fact`] for why: the
//! connector polls `Cuenta/{id}` 24.158 times, the graph does not
//! deduplicate edges, and per-observation stamps would leave ~5×
//! redundant edges inflating precisely the degrees that centrality and
//! anomaly scoring rank on.
//!
//! # What is deliberately not emitted
//!
//! `sId` is a per-request correlation id, not a session: 392.014 distinct
//! values over 1,2M lines, averaging 3,1 lines each, and only 24 of
//! 327.948 span more than one endpoint. As nodes they would be ~392k
//! degree-1 singletons. Balance and movement polling (60.098 + 4.624
//! lines) is likewise dropped: with no session to hang it from it could
//! only attach to a per-endpoint hub, and a synthetic 60k-degree node
//! distorts the centrality and anomaly scores the engine ranks on. The
//! response *contents* of those lookups are kept — it is only the
//! fact-of-the-lookup that is discarded.

use graph_hunter_core::entity::Entity;
use graph_hunter_core::parser::{LogParser, ParsedTriple};
use graph_hunter_core::relation::Relation;
use graph_hunter_core::types::{EntityType, RelationType};
use serde_json::Value;

/// The `saveNewOperationNotification` line is the canonical settled-money
/// record; the `/webhook/…` POST on the neighbouring line repeats it.
const WEBHOOK_MARKER: &str = "saveNewOperationNotification - REQUEST: ";
/// The duplicate of [`WEBHOOK_MARKER`] — matched only so it can be skipped.
const WEBHOOK_DUPLICATE_PATH: &str = "/webhook/newOperationNotification";

/// Detects BIND PSP connector NDJSON: JSON-object lines carrying `line`
/// and `timestamp`, whose text names the connector or its upstream host.
///
/// The envelope alone (`{"line":…,"timestamp":…}`) is far too common a
/// shape to key on — it is roughly every log shipper's output — so the
/// connector signature is required too.
pub fn looks_like_bind_psp(contents: &str) -> bool {
    // Bound the probe; `contents` may be a whole multi-hundred-MB file.
    let cap = contents.len().min(8192);
    let end = (0..=cap)
        .rev()
        .find(|&i| contents.is_char_boundary(i))
        .unwrap_or(0);
    let probe = &contents[..end];

    // `c.p.b.p.c.c.` is Logback's abbreviation of the connector's own
    // package and is the broadest signature available: it covers 86,6% of
    // the corpus this was built against, against 75,1% for `BindPsp`,
    // because the webhook-settlement lines are logged by
    // `CollectionServiceImpl` and never name the connector class at all.
    // A probe landing only on those would otherwise reject the file.
    if !(probe.contains("c.p.b.p.c.c.")
        || probe.contains("BindPsp")
        || probe.contains("bindpagos.com.ar"))
    {
        return false;
    }
    let mut checked = 0;
    for line in probe.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if !(line.starts_with('{') && line.contains("\"line\"") && line.contains("\"timestamp\"")) {
            // The final line of a truncated probe is usually cut mid-way;
            // don't fail the whole file on it.
            break;
        }
        checked += 1;
        if checked >= 3 {
            return true;
        }
    }
    checked > 0
}

// ── small helpers ────────────────────────────────────────────────────

fn digits(s: &str) -> String {
    s.chars().filter(char::is_ascii_digit).collect()
}

fn squash(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Reads a string field, treating JSON `null` and blanks as absent.
fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
    let out = v.get(key)?.as_str()?.trim();
    (!out.is_empty()).then_some(out)
}

/// Reads a field that may be encoded as a number *or* a string — the
/// upstream API is inconsistent (`"cuentaId":1000001` but
/// `"cuitContraparte":"27000000011"`).
fn num_or_str(v: &Value, key: &str) -> Option<String> {
    match v.get(key)? {
        Value::Number(n) => Some(n.to_string()),
        Value::String(t) if !t.trim().is_empty() => Some(t.trim().to_string()),
        _ => None,
    }
}

/// Amounts arrive as `31600.00`, `11400` or occasionally a string.
/// Normalized to two decimals so the same amount keys identically.
fn amount(v: &Value, key: &str) -> Option<String> {
    let n = match v.get(key)? {
        Value::Number(n) => n.as_f64()?,
        Value::String(t) => t.trim().parse().ok()?,
        _ => return None,
    };
    Some(format!("{n:.2}"))
}

/// Parses an RFC 3339 instant to epoch seconds. Covers both the envelope
/// (`2026-09-03T00:00:00.056932647Z`) and payload business times
/// (`2026-09-02T23:59:57.3648729+00:00`).
fn rfc3339_epoch(raw: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(raw.trim())
        .ok()
        .map(|dt| dt.timestamp())
}

/// An 11-digit CUIT/CUIL, or `None`. Unprefixed — see module docs on the
/// identity contract with [`crate::certero`].
fn person(raw: Option<&str>) -> Option<Entity> {
    let d = digits(raw?);
    (d.len() == 11).then(|| Entity::new(d, EntityType::Other("Person".into())))
}

/// A 22-digit CVU/CBU account node.
fn account_cvu(raw: Option<&str>) -> Option<Entity> {
    let d = digits(raw?);
    (d.len() == 22).then(|| Entity::new(d, EntityType::Other("Account".into())))
}

/// The wallet's own account, keyed by upstream internal id.
fn account_internal(raw: Option<&str>) -> Option<Entity> {
    let d = digits(raw?);
    (!d.is_empty()).then(|| Entity::new(format!("acct:{d}"), EntityType::Other("Account".into())))
}

fn tagged(prefix: &str, ty: &str, raw: Option<&str>) -> Option<Entity> {
    let v = squash(raw?);
    (!v.is_empty()).then(|| Entity::new(format!("{prefix}{v}"), EntityType::Other(ty.into())))
}

/// Builds the address node that merges with [`crate::certero`]'s
/// `Domicilio`: `CALLE NUMERO, LOCALIDAD, PROVINCIA`, uppercased.
fn domicilio(d: &Value) -> Option<Entity> {
    let calle = squash(s(d, "calle").unwrap_or(""));
    let numero = squash(s(d, "numero").unwrap_or(""));
    let localidad = squash(s(d, "localidadNombre").unwrap_or(""));
    let provincia = squash(s(d, "provinciaNombre").unwrap_or(""));
    if calle.is_empty() || localidad.is_empty() {
        return None;
    }
    let street = if numero.is_empty() {
        calle
    } else {
        format!("{calle} {numero}")
    };
    let full = if provincia.is_empty() {
        format!("{street}, {localidad}")
    } else {
        format!("{street}, {localidad}, {provincia}")
    }
    .to_uppercase();
    Some(Entity::new(full, EntityType::Other("Domicilio".into())))
}

struct Ctx {
    /// Business time when known, else log time — the edge timestamp.
    ts: i64,
    /// Envelope time, always retained for audit.
    ts_log: i64,
    ts_source: &'static str,
}

/// An **event** edge: something happened between these two nodes at this
/// instant. Carries the real timestamp.
fn rel(src: &Entity, dst: &Entity, name: &str, ctx: &Ctx) -> Relation {
    Relation::new(&src.id, &dst.id, RelationType::Other(name.into()), ctx.ts)
        .with_metadata("ts_log_epoch", ctx.ts_log.to_string())
        .with_metadata("ts_source", ctx.ts_source)
        .with_metadata("fuente", "bind-psp")
}

/// A **standing fact** edge: who holds an account, where they live, which
/// bank an account sits in. Emitted at `timestamp = 0` with
/// `atemporal = "true"`, matching [`crate::certero`], for three reasons.
///
/// 1. It is not an event. Re-reading `Cuenta/{id}` does not mean the
///    holder re-acquired the account; the connector just polled a
///    reference record — 24.158 times in the source corpus.
/// 2. The graph does not deduplicate edges (`Graph::insert_relation_stamped`
///    pushes unconditionally and calls `scorer.observe_edge` on every
///    one), so stamping each re-observation with its own time would leave
///    ~5× redundant edges inflating the degree of exactly the nodes the
///    centrality and anomaly scores rank on.
/// 3. At `timestamp = 0` every re-assertion is byte-identical, so the
///    duplicates collapse exactly under any later dedup pass — whereas
///    per-observation stamps can never be recovered into one fact.
///
/// First-observation time is not lost: it stays in `ts_log_epoch`.
///
/// Deduplication itself is deliberately *not* done here. The ingest
/// pipeline hands this parser independent line batches, so an in-parser
/// cache would make output depend on batch size — unacceptable for
/// forensic reproducibility.
fn fact(src: &Entity, dst: &Entity, name: &str, ctx: &Ctx) -> Relation {
    Relation::new(&src.id, &dst.id, RelationType::Other(name.into()), 0)
        .with_metadata("ts_log_epoch", ctx.ts_log.to_string())
        .with_metadata("atemporal", "true")
        .with_metadata("fuente", "bind-psp")
}

/// Splits `k=v` query pairs.
fn query_param<'a>(query: &'a str, key: &str) -> Option<&'a str> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k.eq_ignore_ascii_case(key) && !v.is_empty()).then_some(v)
    })
}

/// The decomposed shape of a `BindPspFeignLogger` line.
struct Call<'a> {
    verb: &'a str,
    path: &'a str,
    query: &'a str,
    request: &'a str,
    status: &'a str,
    response: &'a str,
}

/// Splits `REQUEST: [VERB] [URL] [BODY] - time_elapsed: [N ms] -
/// RESPONSE: [CODE] [BODY]`.
///
/// Bracket-counting is avoided on purpose: both bodies routinely contain
/// `[` and `]` (`"emails":[]`, `"errores":[{…}]`). Instead the literal
/// separators — which cannot occur inside a JSON body — anchor the split,
/// and each body is taken as the slice between them.
fn split_call(line: &str) -> Option<Call<'_>> {
    let rest = line.split_once("REQUEST: [")?.1;
    let (verb, rest) = rest.split_once("] [")?;
    let (url, rest) = rest.split_once("] [")?;
    let (request, rest) = rest.split_once("] - time_elapsed:")?;
    let after = rest.split_once("RESPONSE: [")?.1;
    let (status, after) = after.split_once(']')?;

    let body = after.trim();
    let response = body
        .strip_prefix('[')
        .and_then(|b| b.strip_suffix(']'))
        .unwrap_or("");

    let (path, query) = url.split_once('?').unwrap_or((url, ""));
    Some(Call {
        verb: verb.trim(),
        path,
        query,
        request: request.trim(),
        status: status.trim(),
        response,
    })
}

/// The last path segment, when it is all digits (`…/Cuenta/1000004`).
fn trailing_id(path: &str) -> Option<&str> {
    let seg = path.rsplit('/').next()?;
    (!seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit())).then_some(seg)
}

pub struct BindPspParser;

impl BindPspParser {
    /// Settled money, from the canonical `saveNewOperationNotification`
    /// line. See module docs for why the `/webhook/…` twin is skipped.
    fn money(&self, payload: &Value, ctx: &Ctx, out: &mut Vec<ParsedTriple>) {
        let Some(evento) = s(payload, "evento") else {
            return;
        };
        let local = account_internal(num_or_str(payload, "cuentaId").as_deref());
        let remote = account_cvu(s(payload, "cvuCbuContraparte"))
            // A counterparty with no CVU is still a party; fall back to
            // their CUIT so the edge is not lost.
            .or_else(|| {
                person(s(payload, "cuitContraparte")).map(|p| {
                    Entity::new(
                        format!("acct:cuit:{}", p.id),
                        EntityType::Other("Account".into()),
                    )
                })
            });
        let (Some(local), Some(mut remote)) = (local, remote) else {
            return;
        };

        if let Some(n) = s(payload, "nombreContraparte") {
            remote = remote.with_metadata("titular_nombre", squash(n));
        }

        // Direction relative to the wallet's account.
        let outgoing = evento.ends_with("SALIENTE") || evento == "PAGO_QR";
        let (src, dst) = if outgoing {
            (local, remote)
        } else {
            (remote, local)
        };

        let mut r = rel(&src, &dst, "Transfer", ctx)
            .with_metadata("evento", evento)
            .with_metadata("settled", "true");
        for (key, field) in [
            ("importe", "importe"),
            ("estado", "operacionEstado"),
            ("operacion_tipo", "operacionTipo"),
            ("referencia", "referencia"),
            ("coelsa_id", "coelsaId"),
            ("mensaje_id", "mensajeId"),
            ("motivo_rechazo", "motivoRechazo"),
            ("banco_contraparte", "bancoContraparte"),
            ("fecha_operacion", "fechaCreacion"),
        ] {
            let v = if key == "importe" {
                amount(payload, field)
            } else {
                num_or_str(payload, field)
            };
            if let Some(v) = v {
                r = r.with_metadata(key, v);
            }
        }
        for (key, field) in [
            ("operacion_id", "operacionId"),
            ("comprobante_id", "comprobanteId"),
            ("operacion_relacionada", "operacionIdRelacionada"),
        ] {
            if let Some(v) = num_or_str(payload, field) {
                r = r.with_metadata(key, v);
            }
        }
        out.push((src.clone(), r, dst.clone()));

        // The counterparty's identity, hung off whichever node is theirs.
        let their = if outgoing { &dst } else { &src };
        if let Some(p) = person(s(payload, "cuitContraparte")) {
            let p = match s(payload, "nombreContraparte") {
                Some(n) => p.with_metadata("nombre", squash(n)),
                None => p,
            };
            out.push((p.clone(), fact(&p, their, "Titular", ctx), their.clone()));
        }
        if let Some(b) = tagged("bco:", "Bank", s(payload, "bancoContraparte")) {
            out.push((their.clone(), fact(their, &b, "EnBanco", ctx), b));
        }
        if let Some(a) = tagged("alias:", "Alias", s(payload, "aliasContraparte")) {
            out.push((their.clone(), fact(their, &a, "TieneAlias", ctx), a));
        }
    }

    /// `POST …/transferir` — a transfer *attempt*. Emitted as
    /// `IntentoTransfer` so it never inflates settled totals, and kept
    /// even on failure: a blocked attempt still names its destination.
    fn transfer_attempt(&self, call: &Call<'_>, ctx: &Ctx, out: &mut Vec<ParsedTriple>) {
        let Ok(req) = serde_json::from_str::<Value>(call.request) else {
            return;
        };
        let (Some(src), Some(dst)) = (
            account_cvu(s(&req, "cvu_origen")),
            account_cvu(s(&req, "cbu_cvu_destino")),
        ) else {
            return;
        };
        let resp: Value = serde_json::from_str(call.response).unwrap_or(Value::Null);
        let ok = call.status == "200";

        let mut r = rel(&src, &dst, "IntentoTransfer", ctx)
            .with_metadata("http_status", call.status)
            .with_metadata("settled", if ok { "true" } else { "false" });
        if let Some(v) = amount(&req, "importe") {
            r = r.with_metadata("importe", v);
        }
        for (key, field) in [("referencia", "referencia"), ("concepto", "concepto")] {
            if let Some(v) = s(&req, field) {
                r = r.with_metadata(key, v);
            }
        }
        if ok {
            for (key, field) in [
                ("coelsa_id", "coelsaId"),
                ("estado", "estadoExterno"),
                ("operacion_id", "operacionId"),
                ("fecha_operacion", "fechaInicio"),
            ] {
                if let Some(v) = num_or_str(&resp, field) {
                    r = r.with_metadata(key, v);
                }
            }
        } else {
            // `{"eventId":…,"detalle":"No se han superado las validaciones
            // en ARDID.","errores":[{"titulo":"Rechazada ARDID",…}]}`
            if let Some(v) = s(&resp, "detalle") {
                r = r.with_metadata("motivo_rechazo", v);
            }
            if let Some(t) = resp
                .get("errores")
                .and_then(Value::as_array)
                .and_then(|e| e.first())
                .and_then(|e| s(e, "titulo"))
            {
                r = r.with_metadata("rechazo_titulo", t);
            }
        }
        out.push((src.clone(), r, dst.clone()));

        if let Some(p) = person(s(&req, "cuit_destino")) {
            out.push((p.clone(), fact(&p, &dst, "Titular", ctx), dst.clone()));
        }
        if let Some(a) = tagged("alias:", "Alias", s(&req, "alias_destino")) {
            out.push((dst.clone(), fact(&dst, &a, "TieneAlias", ctx), a));
        }
        // The 200 response names the origin account both ways — the
        // bridge between the internal-id and CVU id spaces.
        if let Some(internal) = account_internal(num_or_str(&resp, "origenCuentaId").as_deref()) {
            out.push((
                internal.clone(),
                fact(&internal, &src, "MismaCuenta", ctx),
                src.clone(),
            ));
        }
    }

    /// `GET …/Cuenta/{id}` — the richest identity record in the corpus.
    fn account_profile(&self, call: &Call<'_>, ctx: &Ctx, out: &mut Vec<ParsedTriple>) {
        let Ok(r) = serde_json::from_str::<Value>(call.response) else {
            return;
        };
        let Some(cvu) = account_cvu(s(&r, "cvu")) else {
            return;
        };
        if let Some(internal) = account_internal(num_or_str(&r, "id").as_deref()) {
            out.push((
                internal.clone(),
                fact(&internal, &cvu, "MismaCuenta", ctx),
                cvu.clone(),
            ));
        }
        if let Some(mut p) = person(s(&r, "cuitCuil")) {
            for (key, field) in [
                ("nombre", "razonSocial"),
                ("email", "email"),
                ("celular", "celular"),
                ("ocupacion", "ocupacion"),
                ("estado_civil", "estadoCivil"),
                ("fecha_nacimiento", "fechaNacimiento"),
            ] {
                if let Some(v) = s(&r, field) {
                    p = p.with_metadata(key, squash(v));
                }
            }
            // Regulatory flags: politically exposed, UIF-reported, FATCA.
            for (key, field) in [
                ("es_pep", "esPep"),
                ("es_uif", "esUif"),
                ("es_facta", "esFacta"),
            ] {
                if let Some(b) = r.get(field).and_then(Value::as_bool) {
                    p = p.with_metadata(key, if b { "true" } else { "false" });
                }
            }
            out.push((p.clone(), fact(&p, &cvu, "Titular", ctx), cvu.clone()));

            if let Some(d) = r.get("domicilio").and_then(domicilio) {
                out.push((p.clone(), fact(&p, &d, "Reside", ctx), d));
            }
        }
        if let Some(a) = tagged("alias:", "Alias", s(&r, "alias")) {
            out.push((cvu.clone(), fact(&cvu, &a, "TieneAlias", ctx), a));
        }
    }

    /// `GET …/CuentaCVUByCbuCvuOrAlias` — resolves a CVU/alias to its
    /// holder, and is the only place joint holders (`cotitulares`) appear.
    fn cvu_lookup(&self, call: &Call<'_>, ctx: &Ctx, out: &mut Vec<ParsedTriple>) {
        let Ok(r) = serde_json::from_str::<Value>(call.response) else {
            return;
        };
        let Some(cvu) = account_cvu(s(&r, "cbucvu")) else {
            return;
        };
        if let Some(mut p) = person(s(&r, "cuitCuil")) {
            if let Some(n) = s(&r, "nombre") {
                p = p.with_metadata("nombre", squash(n));
            }
            out.push((p.clone(), fact(&p, &cvu, "Titular", ctx), cvu.clone()));
        }
        // A shared account is a strong ring signal, so joint holders get
        // their own relation type rather than collapsing into `Titular`.
        for co in r
            .get("cotitulares")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[])
        {
            if let Some(mut p) = person(s(co, "cuitCuil")) {
                if Some(p.id.as_str()) == s(&r, "cuitCuil").map(digits).as_deref() {
                    continue; // the primary holder, already emitted
                }
                if let Some(n) = s(co, "nombre") {
                    p = p.with_metadata("nombre", squash(n));
                }
                out.push((p.clone(), fact(&p, &cvu, "Cotitular", ctx), cvu.clone()));
            }
        }
        // `entidad` is the wallet brand ("MERCADO LIBRE SRL"), `bancoNombre`
        // the sponsoring bank ("CITIBANK N.A."). They are different facts;
        // prefer the sponsoring bank and keep the other as metadata.
        if let Some(b) = tagged("bco:", "Bank", s(&r, "bancoNombre").or(s(&r, "entidad"))) {
            let mut e = fact(&cvu, &b, "EnBanco", ctx);
            if let Some(v) = s(&r, "entidad") {
                e = e.with_metadata("entidad", v);
            }
            if let Some(v) = s(&r, "tipoCuenta") {
                e = e.with_metadata("tipo_cuenta", v);
            }
            out.push((cvu.clone(), e, b));
        }
        if let Some(a) = tagged("alias:", "Alias", s(&r, "alias")) {
            out.push((cvu.clone(), fact(&cvu, &a, "TieneAlias", ctx), a));
        }
    }

    /// `GET …/CuentaByCuit?cuit=N` — 873 calls, 597 of them `404`.
    ///
    /// The fan-in onto a single `Endpoint` node *is* the signal: a burst
    /// of not-found CUITs is identity enumeration, and the edge timestamps
    /// carry the burst shape.
    fn cuit_probe(&self, call: &Call<'_>, ctx: &Ctx, out: &mut Vec<ParsedTriple>) {
        let Some(p) = person(query_param(call.query, "cuit")) else {
            return;
        };
        let ep = Entity::new("api:CuentaByCuit", EntityType::Other("Endpoint".into()));
        let found = call.status == "200";
        let mut r = rel(&p, &ep, "Consultado", ctx)
            .with_metadata("http_status", call.status)
            .with_metadata("encontrada", if found { "true" } else { "false" });
        if !found
            && let Ok(resp) = serde_json::from_str::<Value>(call.response)
            && let Some(v) = s(&resp, "detalle")
        {
            r = r.with_metadata("detalle", v);
        }
        out.push((p.clone(), r, ep));

        if found {
            self.account_profile(call, ctx, out);
        }
    }

    fn parse_line(&self, raw: &str, out: &mut Vec<ParsedTriple>) {
        let Ok(env) = serde_json::from_str::<Value>(raw) else {
            return;
        };
        let (Some(line), Some(ts_log)) = (
            env.get("line").and_then(Value::as_str),
            env.get("timestamp")
                .and_then(Value::as_str)
                .and_then(rfc3339_epoch),
        ) else {
            return;
        };

        // ── settled money ──
        if let Some(payload) = line.split_once(WEBHOOK_MARKER).map(|x| x.1) {
            let Ok(p) = serde_json::from_str::<Value>(payload.trim()) else {
                return;
            };
            let business = s(&p, "fechaCreacion").and_then(rfc3339_epoch);
            let ctx = Ctx {
                ts: business.unwrap_or(ts_log),
                ts_log,
                ts_source: if business.is_some() {
                    "fechaCreacion"
                } else {
                    "log"
                },
            };
            self.money(&p, &ctx, out);
            return;
        }

        // ── upstream HTTP calls ──
        let Some(call) = split_call(line) else {
            return;
        };
        // The duplicate of the webhook handled above.
        if call.path.ends_with(WEBHOOK_DUPLICATE_PATH) {
            return;
        }
        let ctx = Ctx {
            ts: ts_log,
            ts_log,
            ts_source: "log",
        };

        if call.path.ends_with("/transferir") && call.verb == "POST" {
            self.transfer_attempt(&call, &ctx, out);
        } else if call.path.contains("/CuentaByCuit") {
            self.cuit_probe(&call, &ctx, out);
        } else if call.path.contains("/CuentaCVUByCbuCvuOrAlias") {
            if call.status == "200" {
                self.cvu_lookup(&call, &ctx, out);
            }
        } else if call.status == "200"
            && call.path.contains("/Cuenta/")
            && trailing_id(call.path).is_some()
        {
            self.account_profile(&call, &ctx, out);
        }
        // Balance/movement polling and the reference endpoints
        // (provincias, localidades, QR) are intentionally dropped — see
        // module docs.
    }
}

impl LogParser for BindPspParser {
    fn parse(&self, data: &str) -> Vec<ParsedTriple> {
        let mut out = Vec::new();
        for line in data.lines() {
            let line = line.trim();
            if !line.is_empty() {
                self.parse_line(line, &mut out);
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Lines with the exact shape of the case corpus, one per shape the
    /// parser handles, plus the webhook duplicate that must be skipped.
    /// Every personal or account identifier is synthetic.
    const WEBHOOK_ENTRANTE: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,105 [http-nio-8080-exec-11] INFO  [sId:F0000000000000000000000000000007] c.p.b.p.c.c.s.i.CollectionServiceImpl - saveNewOperationNotification - REQUEST: {\"mensajeId\":\"00000000-0000-4000-8000-000000000001\",\"evento\":\"TRANSFERENCIA_ENTRANTE\",\"operacionId\":900000002,\"operacionTipo\":\"TransferenciaEntrante\",\"operacionEstado\":\"Aprobada\",\"cuentaId\":1000001,\"importe\":31600.00,\"nombreContraparte\":\"Persona Ejemplo Uno\",\"bancoContraparte\":\"0003\",\"referencia\":null,\"cuitContraparte\":\"27000000011\",\"cvuCbuContraparte\":\"0000003100000000000001\",\"aliasContraparte\":null,\"coelsaId\":\"COELSA0000000000000001\",\"idExterno\":null,\"motivoRechazo\":null,\"comprobanteId\":900000101,\"comprobanteDevolucionId\":null,\"fechaCreacion\":\"2026-09-02T23:59:57.3648729+00:00\",\"fechaActualizacion\":\"2026-09-02T23:59:57.3648729+00:00\"}","timestamp":"2026-09-03T00:00:00.106293372Z"}"#;

    /// The duplicate of the line above, as the connector also logs it.
    const WEBHOOK_DUPLICATE: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,105 [http-nio-8080-exec-11] INFO  [sId:F0000000000000000000000000000007] c.p.b.p.c.c.s.i.BindPspServiceImpl - REQUEST: [POST] [/webhook/newOperationNotification] [{\"mensajeId\":\"00000000-0000-4000-8000-000000000001\",\"evento\":\"TRANSFERENCIA_ENTRANTE\",\"operacionId\":900000002,\"importe\":31600.00,\"cuentaId\":1000001,\"cuitContraparte\":\"27000000011\",\"cvuCbuContraparte\":\"0000003100000000000001\"}] - time_elapsed: [1 ms] - RESPONSE: [200] [{}]","timestamp":"2026-09-03T00:00:00.106181911Z"}"#;

    const WEBHOOK_SALIENTE: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,200 [http-nio-8080-exec-9] INFO  [sId:AAAA] c.p.b.p.c.c.s.i.CollectionServiceImpl - saveNewOperationNotification - REQUEST: {\"mensajeId\":\"00000000-0000-4000-8000-000000000003\",\"evento\":\"TRANSFERENCIA_SALIENTE\",\"operacionId\":900000001,\"operacionTipo\":\"TransferenciaSaliente\",\"operacionEstado\":\"Aprobada\",\"cuentaId\":1000002,\"importe\":3300.0,\"nombreContraparte\":\"Persona Ejemplo Dos\",\"bancoContraparte\":\"0003\",\"referencia\":\"Varios\",\"cuitContraparte\":\"20000000012\",\"cvuCbuContraparte\":\"0000003100000000000002\",\"aliasContraparte\":null,\"coelsaId\":\"ABC123\",\"fechaCreacion\":\"2026-09-02T23:59:40+00:00\"}","timestamp":"2026-09-03T00:00:00.200000000Z"}"#;

    const TRANSFER_OK: &str = r#"{"labels":{},"line":"2026-09-03 00:00:17,183 [http-nio-8080-exec-39] INFO  [sId:F0000000000000000000000000000001] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [POST] [https://api.bindpagos.com.ar/walletentidad-operaciones/v1/api/v1.201/transferir] [{\"cvu_origen\":\"0000184300000000000003\",\"cbu_cvu_destino\":\"0000003100000000000004\",\"cuit_destino\":\"23000000013\",\"alias_destino\":\"alias.ejemplo3\",\"importe\":11400,\"referencia\":\"Varios\",\"concepto\":\"VAR\",\"emails\":[],\"idExterno\":null}] - time_elapsed: [8880 ms] - RESPONSE: [200] [{\"operacionId\":900000003,\"estadoExterno\":\"COMPLETED\",\"origenCuentaId\":1000003,\"coelsaId\":\"COELSA0000000000000002\",\"fechaInicio\":\"2026-09-02T23:59:42+00:00\",\"importe\":11400.0,\"cvuOrigen\":\"0000184300000000000003\",\"cvuCbuContraparte\":\"0000003100000000000004\",\"nombreContraparte\":\"Persona Ejemplo Tres\",\"cuitCuilContraparte\":\"23000000013\",\"esTransferenciaInterna\":false}]","timestamp":"2026-09-03T00:00:17.185Z"}"#;

    const TRANSFER_ARDID: &str = r#"{"labels":{},"line":"2026-09-03 00:00:15,306 [http-nio-8080-exec-28] INFO  [sId:F0000000000000000000000000000002] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [POST] [https://api.bindpagos.com.ar/walletentidad-operaciones/v1/api/v1.201/transferir] [{\"cvu_origen\":\"0000184300000000000005\",\"cbu_cvu_destino\":\"0000003100000000000006\",\"cuit_destino\":\"27000000014\",\"alias_destino\":\"alias.ejemplo4\",\"importe\":100000,\"referencia\":\"Varios\",\"concepto\":\"VAR\",\"emails\":[],\"idExterno\":null}] - time_elapsed: [584 ms] - RESPONSE: [409] [{\"eventId\":\"3257\",\"detalle\":\"No se han superado las validaciones en ARDID.\",\"correlationId\":\"00000000-0000-4000-8000-000000000002\",\"errores\":[{\"codigo\":\"3257\",\"titulo\":\"Rechazada ARDID\",\"detalle\":\"No se han superado las validaciones en ARDID.\"}]}]","timestamp":"2026-09-03T00:00:15.309049335Z"}"#;

    const CUENTA: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,225 [http-nio-8080-exec-40] INFO  [sId:F0000000000000000000000000000003] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [GET] [https://api.bindpagos.com.ar/walletentidad-cuenta/v1/api/v1.201/Cuenta/1000004?IncluirDeshabilitadas=true] [] - time_elapsed: [168 ms] - RESPONSE: [200] [{\"id\":1000004,\"cuitCuil\":\"23000000015\",\"nombre\":\"PERSONA EJEMPLO\",\"apellido\":\"SEIS\",\"razonSocial\":\"PERSONA EJEMPLO SEIS\",\"email\":\"persona.seis@example.com\",\"celular\":\"3620000000\",\"habilitado\":true,\"cvu\":\"0000184300000000000007\",\"alias\":\"alias.ejemplo6\",\"domicilio\":{\"calle\":\"Calle Ficticia\",\"numero\":\"123\",\"piso\":\"1\",\"localidadNombre\":\"RESISTENCIA\",\"provinciaNombre\":\"CHACO\"},\"esPep\":false,\"esUif\":false,\"fechaNacimiento\":\"1970-01-01T00:00:00\",\"ocupacion\":\"AMA DE CASA\",\"estadoCivil\":\"CASADO\"}]","timestamp":"2026-09-03T00:00:00.226Z"}"#;

    const CVU_LOOKUP: &str = r#"{"labels":{},"line":"2026-09-03 00:00:03,874 [http-nio-8080-exec-35] INFO  [sId:F0000000000000000000000000000005] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [GET] [https://api.bindpagos.com.ar/walletentidad-cuenta/v1/api/v1.201/CuentaCVUByCbuCvuOrAlias?cbuOrCvu=0000003100000000000006] [] - time_elapsed: [888 ms] - RESPONSE: [200] [{\"cuentaId\":null,\"cbucvu\":\"0000003100000000000006\",\"alias\":\"alias.ejemplo4\",\"cuitCuil\":\"27000000014\",\"nombre\":\"Persona Ejemplo Cuatro\",\"bancoNombre\":\"CITIBANK N.A.\",\"activo\":true,\"nombreCVU\":\"Persona Ejemplo Cuatro\",\"entidad\":\"MERCADO LIBRE SRL\",\"moneda\":\"ARS\",\"tipoCuenta\":\"VIRTUAL\",\"cotitulares\":[{\"cuitCuil\":\"27000000014\",\"nombre\":\"Persona Ejemplo Cuatro\"},{\"cuitCuil\":\"20000000016\",\"nombre\":\"PERSONA EJEMPLO CINCO\"}]}]","timestamp":"2026-09-03T00:00:03.876428968Z"}"#;

    const CUIT_404: &str = r#"{"labels":{},"line":"2026-09-03 00:00:04,421 [http-nio-8080-exec-10] INFO  [sId:F0000000000000000000000000000004] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [GET] [https://api.bindpagos.com.ar/walletentidad-cuenta/v1/api/v1.201/CuentaByCuit?cuit=20000000017] [] - time_elapsed: [132 ms] - RESPONSE: [404] [{\"eventId\":\"11058\",\"detalle\":\"La cuenta no existe\",\"correlationId\":\"00000000-0000-4000-8000-000000000004\",\"errores\":[{\"codigo\":\"11058\",\"titulo\":\"Cuenta no encontrada.\"}]}]","timestamp":"2026-09-03T00:00:04.422432366Z"}"#;

    const SALDO: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,097 [http-nio-8080-exec-44] INFO  [sId:F0000000000000000000000000000006] c.p.b.p.c.c.c.BindPspFeignLogger - REQUEST: [GET] [https://api.bindpagos.com.ar/walletentidad-cuenta/v1/api/v1.201/SaldoActualByIdCuenta/1000005] [] - time_elapsed: [132 ms] - RESPONSE: [200] [{\"saldo\":29060.00}]","timestamp":"2026-09-03T00:00:00.101251562Z"}"#;

    /// A bare service marker — the majority of the corpus. Carries no data.
    const MARKER: &str = r#"{"labels":{},"line":"2026-09-03 00:00:00,049 [http-nio-8080-exec-40] INFO  [sId:F0000000000000000000000000000003] c.p.b.p.c.c.s.i.BindPspServiceImpl - ***** getAccount","timestamp":"2026-09-03T00:00:00.056932647Z"}"#;

    fn edges(data: &str) -> Vec<(String, String, String)> {
        BindPspParser
            .parse(data)
            .into_iter()
            .map(|(s, r, d)| (s.id, r.rel_type.to_string(), d.id))
            .collect()
    }

    fn find<'a>(t: &'a [ParsedTriple], rel_type: &str) -> Option<&'a ParsedTriple> {
        t.iter()
            .find(|(_, r, _)| r.rel_type.to_string() == rel_type)
    }

    #[test]
    fn detects_the_format_and_rejects_others() {
        assert!(looks_like_bind_psp(WEBHOOK_ENTRANTE));
        assert!(looks_like_bind_psp(CUENTA));
        // Right envelope shape, no connector signature — a generic
        // shipper's NDJSON must not be captured.
        assert!(!looks_like_bind_psp(
            r#"{"line":"some app log","timestamp":"2026-09-03T00:00:00Z"}"#
        ));
        assert!(!looks_like_bind_psp(
            r#"{"MSec":"1","EventName":"x","PID":"1"}"#
        ));
        assert!(!looks_like_bind_psp("CUIL\tNOMBRE\n1\ta\n"));
        assert!(!looks_like_bind_psp(""));
    }

    /// The probe slices at a byte offset; a multibyte character straddling
    /// it must not panic.
    #[test]
    fn detection_survives_a_multibyte_boundary() {
        let padded = format!("{}{}", "ñ".repeat(5000), WEBHOOK_ENTRANTE);
        let _ = looks_like_bind_psp(&padded);
    }

    /// The core anti-double-count guarantee: the same settled movement is
    /// logged twice and the parser must value it once.
    #[test]
    fn the_webhook_duplicate_is_not_counted_twice() {
        let both = format!("{WEBHOOK_ENTRANTE}\n{WEBHOOK_DUPLICATE}\n");
        let transfers: Vec<_> = BindPspParser
            .parse(&both)
            .into_iter()
            .filter(|(_, r, _)| r.rel_type.to_string() == "Transfer")
            .collect();
        assert_eq!(
            transfers.len(),
            1,
            "the /webhook/ twin must be skipped, got {transfers:?}"
        );
        assert_eq!(transfers[0].1.metadata["importe"], "31600.00");
    }

    /// Direction is the analytic payload: ENTRANTE credits us, SALIENTE
    /// debits us.
    #[test]
    fn direction_follows_the_evento() {
        let t = BindPspParser.parse(WEBHOOK_ENTRANTE);
        let (src, rel, dst) = find(&t, "Transfer").unwrap();
        assert_eq!(src.id, "0000003100000000000001", "counterparty pays in");
        assert_eq!(dst.id, "acct:1000001", "…into the wallet account");
        assert_eq!(rel.metadata["evento"], "TRANSFERENCIA_ENTRANTE");

        let t = BindPspParser.parse(WEBHOOK_SALIENTE);
        let (src, _, dst) = find(&t, "Transfer").unwrap();
        assert_eq!(src.id, "acct:1000002", "wallet account pays out");
        assert_eq!(dst.id, "0000003100000000000002");
    }

    /// Money edges are timestamped on the settlement clock, not the log
    /// clock, so a chain of hops cannot transpose.
    #[test]
    fn money_edges_use_business_time() {
        let t = BindPspParser.parse(WEBHOOK_ENTRANTE);
        let (_, rel, _) = find(&t, "Transfer").unwrap();
        // fechaCreacion 2026-09-02T23:59:57Z — three seconds *before* the
        // log envelope's 2026-09-03T00:00:00Z, and on the previous day.
        assert_eq!(rel.timestamp, 1788393597);
        assert_eq!(rel.metadata["ts_source"], "fechaCreacion");
        assert_eq!(rel.metadata["ts_log_epoch"], "1788393600");
        assert_eq!(rel.metadata["coelsa_id"], "COELSA0000000000000001");
    }

    #[test]
    fn counterparty_identity_hangs_off_their_account() {
        let e = edges(WEBHOOK_ENTRANTE);
        assert!(e.contains(&(
            "27000000011".into(),
            "Titular".into(),
            "0000003100000000000001".into()
        )));
        assert!(e.contains(&(
            "0000003100000000000001".into(),
            "EnBanco".into(),
            "bco:0003".into()
        )));
    }

    /// A successful transfer must be an *attempt*, never a second
    /// `Transfer`, or every total inflates.
    #[test]
    fn transfers_are_attempts_not_settlements() {
        let t = BindPspParser.parse(TRANSFER_OK);
        assert!(
            find(&t, "Transfer").is_none(),
            "settled money comes only from webhooks"
        );
        let (src, rel, dst) = find(&t, "IntentoTransfer").unwrap();
        assert_eq!(src.id, "0000184300000000000003");
        assert_eq!(dst.id, "0000003100000000000004");
        assert_eq!(rel.metadata["importe"], "11400.00");
        assert_eq!(rel.metadata["settled"], "true");
        assert_eq!(rel.metadata["coelsa_id"], "COELSA0000000000000002");
    }

    /// The rejection path exists in no webhook — losing it would lose the
    /// blocked-fraud evidence entirely.
    #[test]
    fn rejected_transfers_keep_their_destination_and_reason() {
        let t = BindPspParser.parse(TRANSFER_ARDID);
        let (src, rel, dst) = find(&t, "IntentoTransfer").unwrap();
        assert_eq!(src.id, "0000184300000000000005");
        assert_eq!(dst.id, "0000003100000000000006");
        assert_eq!(rel.metadata["http_status"], "409");
        assert_eq!(rel.metadata["settled"], "false");
        assert_eq!(rel.metadata["importe"], "100000.00");
        assert_eq!(rel.metadata["rechazo_titulo"], "Rechazada ARDID");
        assert!(rel.metadata["motivo_rechazo"].contains("ARDID"));
        // …and still names who was being paid.
        assert!(edges(TRANSFER_ARDID).contains(&(
            "27000000014".into(),
            "Titular".into(),
            "0000003100000000000006".into()
        )));
    }

    /// The bridge that lets traversal cross from internal account ids to
    /// CVUs. Without it the webhook graph and the transfer graph are two
    /// disconnected components.
    #[test]
    fn account_profile_bridges_the_two_id_spaces() {
        let e = edges(CUENTA);
        assert!(e.contains(&(
            "acct:1000004".into(),
            "MismaCuenta".into(),
            "0000184300000000000007".into()
        )));
        assert!(e.contains(&(
            "23000000015".into(),
            "Titular".into(),
            "0000184300000000000007".into()
        )));
        // The transfer response carries the same bridge.
        assert!(edges(TRANSFER_OK).contains(&(
            "acct:1000003".into(),
            "MismaCuenta".into(),
            "0000184300000000000003".into()
        )));
    }

    /// The address node must be byte-identical to `certero`'s so a PSP
    /// account holder and a dossier row collapse onto one `Domicilio`.
    #[test]
    fn addresses_match_the_certero_shape() {
        assert!(edges(CUENTA).contains(&(
            "23000000015".into(),
            "Reside".into(),
            "CALLE FICTICIA 123, RESISTENCIA, CHACO".into()
        )));
    }

    #[test]
    fn account_profile_carries_regulatory_flags() {
        let t = BindPspParser.parse(CUENTA);
        let (p, _, _) = find(&t, "Titular").unwrap();
        assert_eq!(p.metadata["nombre"], "PERSONA EJEMPLO SEIS");
        assert_eq!(p.metadata["email"], "persona.seis@example.com");
        assert_eq!(p.metadata["es_pep"], "false");
        assert_eq!(p.metadata["es_uif"], "false");
        assert_eq!(p.metadata["ocupacion"], "AMA DE CASA");
    }

    /// Joint holders get their own relation type — a shared account is a
    /// ring signal, not an ordinary ownership fact.
    #[test]
    fn joint_holders_are_distinguished_from_the_titular() {
        let e = edges(CVU_LOOKUP);
        assert!(e.contains(&(
            "27000000014".into(),
            "Titular".into(),
            "0000003100000000000006".into()
        )));
        assert!(
            e.contains(&(
                "20000000016".into(),
                "Cotitular".into(),
                "0000003100000000000006".into()
            )),
            "second holder missing: {e:?}"
        );
        // The primary holder also appears in `cotitulares`; they must not
        // get a duplicate self-edge.
        assert_eq!(e.iter().filter(|(s, _, _)| s == "27000000014").count(), 1);
        assert!(e.contains(&(
            "0000003100000000000006".into(),
            "EnBanco".into(),
            "bco:CITIBANK N.A.".into()
        )));
    }

    /// The enumeration signal: probed CUITs fan into one endpoint node.
    #[test]
    fn failed_cuit_lookups_are_kept_as_the_enumeration_signal() {
        let t = BindPspParser.parse(CUIT_404);
        let (p, rel, ep) = find(&t, "Consultado").unwrap();
        assert_eq!(p.id, "20000000017");
        assert_eq!(ep.id, "api:CuentaByCuit");
        assert_eq!(rel.metadata["http_status"], "404");
        assert_eq!(rel.metadata["encontrada"], "false");
        assert_eq!(rel.metadata["detalle"], "La cuenta no existe");
    }

    /// Events keep real time; standing facts do not. Re-reading an
    /// account record must not look like the holder re-acquired it, or
    /// ~5× redundant edges inflate the degrees that the centrality and
    /// anomaly scores rank on.
    #[test]
    fn identity_edges_are_atemporal_and_event_edges_are_not() {
        const FACTS: &[&str] = &[
            "Titular",
            "Cotitular",
            "MismaCuenta",
            "TieneAlias",
            "EnBanco",
            "Reside",
        ];
        const EVENTS: &[&str] = &["Transfer", "IntentoTransfer", "Consultado"];

        let all = format!(
            "{WEBHOOK_ENTRANTE}\n{TRANSFER_OK}\n{TRANSFER_ARDID}\n{CUENTA}\n{CVU_LOOKUP}\n{CUIT_404}\n"
        );
        let t = BindPspParser.parse(&all);
        let mut seen_fact = 0;
        let mut seen_event = 0;
        for (_, r, _) in &t {
            let name = r.rel_type.to_string();
            if FACTS.contains(&name.as_str()) {
                seen_fact += 1;
                assert_eq!(r.timestamp, 0, "{name} must be atemporal");
                assert_eq!(r.metadata["atemporal"], "true");
                // First observation is still recoverable.
                assert!(r.metadata.contains_key("ts_log_epoch"));
            } else if EVENTS.contains(&name.as_str()) {
                seen_event += 1;
                assert!(r.timestamp > 0, "{name} must carry a real time");
                assert!(!r.metadata.contains_key("atemporal"));
            } else {
                panic!("unclassified relation {name}");
            }
        }
        assert!(seen_fact > 0 && seen_event > 0);
    }

    /// Polling and bare service markers must contribute nothing — see the
    /// module docs on why a 60k-degree hub is worse than no edge.
    #[test]
    fn polling_and_markers_emit_nothing() {
        assert!(BindPspParser.parse(SALDO).is_empty());
        assert!(BindPspParser.parse(MARKER).is_empty());
    }

    #[test]
    fn malformed_lines_are_skipped_not_fatal() {
        let bad = format!(
            "not json\n{{\"line\":123}}\n{{\"line\":\"x\",\"timestamp\":\"nope\"}}\n{WEBHOOK_ENTRANTE}\n"
        );
        let t = BindPspParser.parse(&bad);
        assert_eq!(
            t.iter()
                .filter(|(_, r, _)| r.rel_type.to_string() == "Transfer")
                .count(),
            1
        );
    }

    /// The streaming ingest path hands the parser independent line
    /// batches, so a batch must parse identically whether it arrives
    /// whole or split.
    #[test]
    fn parsing_is_stateless_across_lines() {
        let all = format!("{WEBHOOK_ENTRANTE}\n{TRANSFER_OK}\n{CUENTA}\n{CVU_LOOKUP}\n");
        let whole = edges(&all);
        let piecewise: Vec<_> = [WEBHOOK_ENTRANTE, TRANSFER_OK, CUENTA, CVU_LOOKUP]
            .iter()
            .flat_map(|l| edges(l))
            .collect();
        assert_eq!(whole, piecewise);
    }
}
