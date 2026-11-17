//! One identity for an account that sources spell differently.
//!
//! Windows logs name an account `CORP\jperez`; an identity provider names
//! the same account `jperez@corp.example`. A node's identity is its id, so
//! those are two `User` nodes and no path crosses from a sign-in to what
//! the account then ran.
//!
//! They cannot be merged by guessing. Dropping the domain would also merge
//! `WS-01\administrator` with `WS-02\administrator` — different accounts —
//! which is the same mistake a host-less process id made
//! (`process_identity`). So the equivalence is declared by the operator:
//!
//! ```text
//! GRAPHHUNTER_DOMAIN_ALIASES=CORP=corp.example,LAB=lab.example
//! ```
//!
//! With that, `corp\jperez` becomes `jperez@corp.example`. Accounts of a
//! domain that is not listed keep the id they always had.

use std::collections::HashMap;
use std::sync::OnceLock;

/// NetBIOS domain (lowercase) → DNS domain (lowercase).
pub type DomainAliases = HashMap<String, String>;

/// Environment variable holding `NETBIOS=dns.domain` pairs, comma-separated.
pub const DOMAIN_ALIASES_ENV: &str = "GRAPHHUNTER_DOMAIN_ALIASES";

/// Parses `CORP=corp.example,LAB=lab.example`. Malformed pairs are skipped.
pub fn parse_aliases(raw: &str) -> DomainAliases {
    raw.split(',')
        .filter_map(|pair| {
            let (netbios, dns) = pair.split_once('=')?;
            let (netbios, dns) = (netbios.trim(), dns.trim());
            (!netbios.is_empty() && !dns.is_empty())
                .then(|| (netbios.to_lowercase(), dns.to_lowercase()))
        })
        .collect()
}

fn env_aliases() -> &'static DomainAliases {
    static ALIASES: OnceLock<DomainAliases> = OnceLock::new();
    ALIASES.get_or_init(|| {
        std::env::var(DOMAIN_ALIASES_ENV)
            .map(|raw| parse_aliases(&raw))
            .unwrap_or_default()
    })
}

/// Canonical id for an account name that is already lowercased.
/// `domain\user` with a declared domain becomes `user@dns.domain`;
/// everything else is returned unchanged.
pub fn canonical_account_with(account: &str, aliases: &DomainAliases) -> String {
    if let Some((domain, user)) = account.split_once('\\')
        && !user.is_empty()
        && let Some(dns) = aliases.get(domain)
    {
        return format!("{user}@{dns}");
    }
    account.to_string()
}

/// [`canonical_account_with`] using the aliases from the environment.
pub fn canonical_account(account: &str) -> String {
    let aliases = env_aliases();
    if aliases.is_empty() {
        return account.to_string();
    }
    canonical_account_with(account, aliases)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_domain_joins_both_spellings() {
        let aliases = parse_aliases("CORP=corp.example, LAB = Lab.Example");
        assert_eq!(
            canonical_account_with("corp\\svc-backup", &aliases),
            "svc-backup@corp.example"
        );
        assert_eq!(
            canonical_account_with("lab\\ana", &aliases),
            "ana@lab.example"
        );
        // The IdP spelling is already the canonical one.
        assert_eq!(
            canonical_account_with("svc-backup@corp.example", &aliases),
            "svc-backup@corp.example"
        );
    }

    #[test]
    fn undeclared_domains_are_left_alone() {
        let aliases = parse_aliases("CORP=corp.example");
        // Local accounts on two machines are different accounts.
        assert_eq!(
            canonical_account_with("ws-01\\administrator", &aliases),
            "ws-01\\administrator"
        );
        assert_eq!(canonical_account_with("jperez", &aliases), "jperez");
        assert_eq!(canonical_account_with("corp\\", &aliases), "corp\\");
    }

    #[test]
    fn malformed_pairs_are_skipped() {
        let aliases = parse_aliases("CORP=corp.example,,=x,BROKEN,LAB=");
        assert_eq!(aliases.len(), 1);
        assert!(aliases.contains_key("corp"));
    }
}
