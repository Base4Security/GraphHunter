//! End-to-end check that the GeoIP wiring actually resolves an address.
//!
//! Everything between the `.mmdb` files and `capabilities()` was in place
//! for a long time while `graph_summary` still reported
//! `geoip:false, asn:false`, because nothing ever populated the provider
//! slot. Unit tests could not have caught that — it only shows up when a
//! real database is present and the bootstrap runs. This test therefore
//! skips (rather than fails) when the databases are absent, so CI without
//! them stays green, but it fails loudly if they exist and the wiring is
//! broken again.

use std::path::PathBuf;

fn bundled_geoip_dir() -> Option<PathBuf> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../apps/tauri/src-tauri/resources/geoip");
    let has_db = dir.join("GeoLite2-City.mmdb").exists() || dir.join("GeoLite2-ASN.mmdb").exists();
    has_db.then_some(dir)
}

#[test]
fn bootstrap_lights_up_geoip_and_asn_capabilities() {
    let Some(dir) = bundled_geoip_dir() else {
        eprintln!("skipped: no .mmdb in resources/geoip (see that dir's README)");
        return;
    };

    let api = graph_hunter_api::GraphHunterApi::new_noop();

    // Before the bootstrap the slots are empty, which is exactly the
    // state that shipped: feature compiled in, provider never installed.
    let before = api.capabilities();
    assert!(!before.geoip, "provider slot must start empty");

    let (mmdb_loaded, _http) = api.bootstrap_geoip(Some(dir));
    assert!(mmdb_loaded, "bootstrap must load the databases it was handed");

    let after = api.capabilities();
    assert!(after.geoip, "geoip capability must be true after bootstrap");
    assert!(
        after.asn,
        "asn capability must be true with a local MMDB present"
    );
}

/// The capability flag only says a database is loaded. This asserts the
/// lookup path returns real data, which is what an analyst actually needs
/// — country for geography, ASN to tell a residential CGNAT range from a
/// hosting provider.
#[test]
fn resolves_a_known_address_to_country_and_asn() {
    let Some(dir) = bundled_geoip_dir() else {
        eprintln!("skipped: no .mmdb in resources/geoip");
        return;
    };
    let provider = graph_hunter_core::geoip::maxmind::MaxMindProvider::from_directory(&dir)
        .expect("open .mmdb");
    assert!(provider.is_available());

    // Google Public DNS: stable, unambiguously US / AS15169.
    let r = provider
        .lookup("8.8.8.8")
        .expect("8.8.8.8 must resolve in GeoLite2");
    assert_eq!(r.country_code.as_deref(), Some("US"), "got {r:?}");
    assert_eq!(r.asn, Some(15169), "got {r:?}");
    assert!(
        r.as_org.is_some(),
        "AS org drives the hosting-vs-residential call: {r:?}"
    );
}
