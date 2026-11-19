//! Identity of a `Process` node.
//!
//! A node's identity is its id alone (see `impl PartialEq for Entity`),
//! and for a long time a process id was just its image path. That makes
//! `powershell.exe` one node for the whole network: a path can then walk
//! `user A -> OUTLOOK.EXE -> powershell.exe -> domain` using edges that
//! are each real but belong to different hosts — a chain nobody ran.
//! Measured with `scripts/eval/`: the hunt attributed the planted C2
//! lookup to the wrong user, a different one on every run.
//!
//! Every parser that emits a `Process` builds its id here, so two sources
//! describing the same process still join, and none can drift from the
//! scheme on its own.

/// What a log event says about one process.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessRef<'a> {
    /// Host the process ran on, already normalized by the caller
    /// (lowercased by `GenericParser::normalize`). `None` when the event
    /// does not say.
    pub host: Option<&'a str>,
    /// Image path or name, as logged.
    pub image: &'a str,
    /// Sysmon `ProcessGuid`: unique per process instance across reboots
    /// and pid reuse. Most sources do not carry one.
    pub guid: Option<&'a str>,
    /// OS pid. Reused over time, and unique only within one host.
    pub pid: Option<&'a str>,
}

/// Separates the scope from the image inside a process id. `|` cannot
/// appear in a Windows path or a hostname, so [`image_of`] can split on
/// the last one without ambiguity.
pub const SCOPE_SEP: char = '|';

/// The node id for `p`: `host|guid|image` when the source identifies the
/// process instance, `host|image` when it does not.
///
/// Measured on `scripts/eval/` (300k events, one planted intrusion): with
/// the instance in the id the hunt attributes the C2 lookup to the one
/// user who made it; `host|image` alone names 30, because several users
/// run the same image on one host. The fallback is therefore sound across
/// hosts but not across executions on the same host.
///
/// The pid is deliberately not part of the id: it is reused over time and
/// missing from many events, so the same process would split into nodes
/// that no longer join.
///
/// Whatever precedes the image ends with [`SCOPE_SEP`], so that
/// [`image_of`] recovers the image.
pub fn process_id(p: &ProcessRef<'_>) -> String {
    let image = escape(p.image);
    match (p.host, p.guid) {
        (Some(host), Some(guid)) => {
            format!(
                "{}{SCOPE_SEP}{}{SCOPE_SEP}{image}",
                escape(host),
                escape(guid)
            )
        }
        (Some(host), None) => format!("{}{SCOPE_SEP}{image}", escape(host)),
        // No host: the guid still separates instances; with neither, the
        // image is all the source gave us.
        (None, Some(guid)) => format!("{}{SCOPE_SEP}{image}", escape(guid)),
        (None, None) => image.into_owned(),
    }
}

/// Encodes [`SCOPE_SEP`] inside one component. Log values are untrusted:
/// an image logged as `x|C:\Windows\System32\svchost.exe` would otherwise
/// make [`image_of`] return the path of `svchost.exe`, and the process
/// would be scored with the rarity of a common system binary.
fn escape(part: &str) -> std::borrow::Cow<'_, str> {
    if part.contains(SCOPE_SEP) {
        std::borrow::Cow::Owned(part.replace(SCOPE_SEP, "%7C"))
    } else {
        std::borrow::Cow::Borrowed(part)
    }
}

/// The image a process id was built from. Ids written before scoping
/// (no separator) are returned whole.
pub fn image_of(id: &str) -> &str {
    id.rsplit_once(SCOPE_SEP).map_or(id, |(_, image)| image)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_of_strips_the_scope_and_keeps_unscoped_ids() {
        assert_eq!(
            image_of("ws-042|C:\\Windows\\cmd.exe"),
            "C:\\Windows\\cmd.exe"
        );
        assert_eq!(image_of("ws-042|4820|cmd.exe"), "cmd.exe");
        assert_eq!(image_of("C:\\Windows\\cmd.exe"), "C:\\Windows\\cmd.exe");
    }

    // Instance identifiers qualify a process; they must never be offered
    // as nodes. Before this they fell through to the name heuristic and
    // every ProcessGuid became its own `Process` node.
    #[test]
    fn instance_identifiers_are_not_entity_fields() {
        use crate::generic::GenericParser;
        for field in [
            "ProcessGuid",
            "ParentProcessGuid",
            "ProcessId",
            "ParentProcessId",
        ] {
            let canonical = GenericParser::canonical_field(field);
            assert_eq!(canonical, Some("process_instance"), "{field}");
            assert_eq!(
                GenericParser::canonical_to_entity_type("process_instance"),
                "Skip"
            );
        }
    }

    #[test]
    fn a_separator_inside_a_component_cannot_change_the_image() {
        let common = "C:\\Windows\\System32\\svchost.exe";
        let disguised = format!("evil{SCOPE_SEP}{common}");
        for (host, guid) in [
            (Some("ws-1"), Some("{g}")),
            (Some("ws-1"), None),
            (None, None),
        ] {
            let id = process_id(&ProcessRef {
                host,
                image: &disguised,
                guid,
                pid: None,
            });
            assert_ne!(image_of(&id), common, "{id}");
            assert!(image_of(&id).starts_with("evil%7C"), "{id}");
        }
        // And a hostile host or guid cannot shift where the image starts.
        let id = process_id(&ProcessRef {
            host: Some("a|b"),
            image: "cmd.exe",
            guid: Some("g|h"),
            pid: None,
        });
        assert_eq!(id.matches(SCOPE_SEP).count(), 2);
        assert_eq!(image_of(&id), "cmd.exe");
    }

    #[test]
    fn process_id_round_trips_through_image_of() {
        let p = ProcessRef {
            host: Some("ws-042"),
            image: "C:\\Windows\\cmd.exe",
            guid: Some("{0f3a}"),
            pid: Some("4820"),
        };
        assert_eq!(image_of(&process_id(&p)), p.image);
    }
}
