//! GeoIP and ASN enrichment for IP addresses.
//!
//! Provides two backends:
//! - **Offline** (feature `geoip`): MaxMind GeoLite2 `.mmdb` files loaded
//!   from a directory. Zero network traffic, zero rate limits.
//! - **HTTP fallback** (always compiled): Uses the `HttpClient` trait to
//!   query a free GeoIP API (ip-api.com) for IPs not resolved offline.
//!
//! Both return a [`GeoIpResult`] with country, city, ASN, and ISP info.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Which source a GeoIP result came from. Useful for the UI to surface a
/// trust indicator — dataset-metadata enrichment is a weaker signal than
/// a fresh MaxMind lookup, and the analyst deserves to know which one
/// they're looking at.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum GeoIpSource {
    #[default]
    Maxmind,
    Http,
    /// Pulled from the entity's pre-existing metadata (e.g. `location` fields
    /// already present from the Sentinel ingest pipeline). Used as a fallback
    /// when neither a MaxMind provider nor an HTTP provider is available —
    /// the feedback called this "the enrichment was already there; just don't
    /// lie about its source".
    DatasetMetadata,
}

/// Result of a GeoIP/ASN lookup for a single IP address.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GeoIpResult {
    pub country_code: Option<String>,
    pub country_name: Option<String>,
    pub city: Option<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub isp: Option<String>,
    pub is_anonymous_proxy: Option<bool>,
    /// Provenance of this result. Optional so old cached values deserialize
    /// cleanly and so `Default::default()` still works without fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<GeoIpSource>,
}

/// Errors from the GeoIP subsystem.
#[derive(Debug)]
pub enum GeoIpError {
    Io(std::io::Error),
    /// 0.28 rename: `MaxMindDBError` (camel + acronym) became
    /// `MaxMindDbError` (camel + lower 'b'). Pin the new name behind
    /// the `geoip` feature so non-geoip builds don't compile against
    /// the dep.
    #[cfg(feature = "geoip")]
    MaxMind(maxminddb::MaxMindDbError),
    Http(String),
    NotPublicIp,
}

impl std::fmt::Display for GeoIpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpError::Io(e) => write!(f, "IO error: {e}"),
            #[cfg(feature = "geoip")]
            GeoIpError::MaxMind(e) => write!(f, "MaxMind error: {e}"),
            GeoIpError::Http(e) => write!(f, "HTTP GeoIP error: {e}"),
            GeoIpError::NotPublicIp => write!(f, "IP is not public/routable"),
        }
    }
}

impl std::error::Error for GeoIpError {}

// ---------------------------------------------------------------------------
// MaxMind offline provider (behind `geoip` feature)
// ---------------------------------------------------------------------------

#[cfg(feature = "geoip")]
pub mod maxmind {
    use super::*;
    use maxminddb::{Reader, geoip2};
    use std::net::IpAddr;

    /// Offline GeoIP provider using MaxMind GeoLite2 `.mmdb` databases.
    ///
    /// Loads `GeoLite2-City.mmdb` and `GeoLite2-ASN.mmdb` from a directory.
    /// Either or both can be missing — the provider returns whatever data
    /// the loaded databases can provide.
    pub struct MaxMindProvider {
        city_reader: Option<Reader<Vec<u8>>>,
        asn_reader: Option<Reader<Vec<u8>>>,
    }

    impl MaxMindProvider {
        /// Loads `.mmdb` files from `dir`. Silently ignores missing files.
        pub fn from_directory(dir: &Path) -> Result<Self, GeoIpError> {
            let city_path = dir.join("GeoLite2-City.mmdb");
            let asn_path = dir.join("GeoLite2-ASN.mmdb");

            let city_reader = if city_path.exists() {
                Some(Reader::open_readfile(&city_path).map_err(GeoIpError::MaxMind)?)
            } else {
                None
            };
            let asn_reader = if asn_path.exists() {
                Some(Reader::open_readfile(&asn_path).map_err(GeoIpError::MaxMind)?)
            } else {
                None
            };

            Ok(Self {
                city_reader,
                asn_reader,
            })
        }

        /// Returns `true` if at least one database is loaded.
        pub fn is_available(&self) -> bool {
            self.city_reader.is_some() || self.asn_reader.is_some()
        }

        /// Looks up a single IP address.
        ///
        /// maxminddb 0.28 API notes (RUSTSEC-2025-0132 forced the bump from
        /// 0.24): `Reader::lookup` is no longer generic — it returns a
        /// `LookupResult<'_, _>` handle whose `.decode::<T>()` does the real
        /// deserialization and returns `Result<Option<T>, _>`. The nested
        /// `country` / `city` fields on `geoip2::City` are now direct
        /// structs (not `Option`), with `is_empty()` guards; the localized
        /// `names` map is no longer a `BTreeMap<&str,&str>` but a typed
        /// `Names<'a>` with one field per language (English here).
        /// `is_anonymous_proxy` no longer exists on `Traits` in 0.28 — we
        /// always emit `None` for that field rather than fabricating a
        /// value (callers already tolerate `None`).
        pub fn lookup(&self, ip_str: &str) -> Option<GeoIpResult> {
            let addr: IpAddr = ip_str.trim().parse().ok()?;
            let mut result = GeoIpResult::default();

            if let Some(reader) = &self.city_reader {
                if let Ok(lookup) = reader.lookup(addr) {
                    if let Ok(Some(city)) = lookup.decode::<geoip2::City>() {
                        if !city.country.is_empty() {
                            result.country_code = city.country.iso_code.map(|s| s.to_string());
                            result.country_name =
                                city.country.names.english.map(|s| s.to_string());
                        }
                        if !city.city.is_empty() {
                            result.city = city.city.names.english.map(|s| s.to_string());
                        }
                        // 0.28: `Traits::is_anonymous_proxy` was removed
                        // upstream; the field is no longer surfaced. Leave
                        // `result.is_anonymous_proxy` as `None`.
                    }
                }
            }

            if let Some(reader) = &self.asn_reader {
                if let Ok(lookup) = reader.lookup(addr) {
                    if let Ok(Some(asn)) = lookup.decode::<geoip2::Asn>() {
                        result.asn = asn.autonomous_system_number;
                        result.as_org =
                            asn.autonomous_system_organization.map(|s| s.to_string());
                        // Use AS org as ISP approximation.
                        result.isp = result.as_org.clone();
                    }
                }
            }

            if result.country_code.is_some() || result.asn.is_some() {
                result.source = Some(GeoIpSource::Maxmind);
                Some(result)
            } else {
                None
            }
        }
    }
}

// ---------------------------------------------------------------------------
// HTTP fallback provider (always compiled)
// ---------------------------------------------------------------------------

pub mod http {
    use super::*;
    use graph_hunter_sources::http_client::{HttpClient, HttpMethod, HttpRequest, StatusClass};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio_util::sync::CancellationToken;

    /// HTTP-based GeoIP fallback using ip-api.com (free tier, 45 req/min).
    pub struct HttpGeoIpProvider {
        client: Arc<dyn HttpClient>,
    }

    impl HttpGeoIpProvider {
        pub fn new(client: Arc<dyn HttpClient>) -> Self {
            Self { client }
        }

        /// Looks up a single IP via the ip-api.com JSON endpoint.
        pub async fn lookup(
            &self,
            ip: &str,
            cancel: CancellationToken,
        ) -> Result<GeoIpResult, GeoIpError> {
            if cancel.is_cancelled() {
                return Err(GeoIpError::Http("cancelled".into()));
            }

            let url = format!(
                "http://ip-api.com/json/{}?fields=status,message,country,countryCode,city,isp,org,as,asname",
                ip
            );

            let request = HttpRequest {
                method: HttpMethod::Get,
                url,
                headers: vec![],
                body: None,
                timeout: Some(Duration::from_secs(10)),
            };

            let response = self
                .client
                .send(request, cancel)
                .await
                .map_err(|e| GeoIpError::Http(format!("{e}")))?;

            if response.status_class() != StatusClass::Success {
                return Err(GeoIpError::Http(format!(
                    "HTTP {} from ip-api.com",
                    response.status
                )));
            }

            let body = String::from_utf8_lossy(&response.body);
            let json: serde_json::Value =
                serde_json::from_str(&body).map_err(|e| GeoIpError::Http(e.to_string()))?;

            if json.get("status").and_then(|s| s.as_str()) != Some("success") {
                let msg = json
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("unknown error");
                return Err(GeoIpError::Http(format!("ip-api.com: {msg}")));
            }

            let asn_str = json.get("as").and_then(|v| v.as_str()).unwrap_or("");
            let asn_num: Option<u32> = asn_str
                .split_whitespace()
                .next()
                .and_then(|s| s.strip_prefix("AS"))
                .and_then(|n| n.parse().ok());

            Ok(GeoIpResult {
                country_code: json
                    .get("countryCode")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                country_name: json
                    .get("country")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                city: json
                    .get("city")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                asn: asn_num,
                as_org: json
                    .get("asname")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                isp: json
                    .get("isp")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                is_anonymous_proxy: None,
                source: Some(GeoIpSource::Http),
            })
        }
    }
}

/// Writes GeoIP enrichment result into an entity's metadata HashMap.
/// Extract a GeoIpResult from pre-existing entity metadata (the ingest
/// pipeline — e.g. Sentinel — sometimes already carries country/city/ASN
/// fields). Returns `None` if none of the expected keys are present.
///
/// This is the fallback path when neither a MaxMind nor an HTTP provider
/// is configured: instead of erroring out, we surface the enrichment that
/// was already there, clearly marked as `GeoIpSource::DatasetMetadata`
/// so the UI can display a distinct badge.
pub fn geoip_from_metadata(
    metadata: &std::collections::HashMap<String, String>,
) -> Option<GeoIpResult> {
    let get = |keys: &[&str]| -> Option<String> {
        for k in keys {
            if let Some(v) = metadata.get(*k) {
                if !v.is_empty() {
                    return Some(v.clone());
                }
            }
        }
        None
    };

    let country_code = get(&["geo_country_code", "country_code", "countryCode"]);
    let country_name = get(&["geo_country", "country", "countryName"]);
    let city = get(&["geo_city", "city"]);
    let asn_str = get(&["geo_asn", "asn"]);
    let as_org = get(&["geo_as_org", "as_org", "as_organization"]);
    let isp = get(&["geo_isp", "isp"]);
    let location = get(&["location"]);

    // If the only signal is a composite `location` string, try to coerce
    // it into country_name (common Sentinel shape: "US - California - ...").
    let country_name = country_name.or_else(|| location.clone());

    // 2026-05-06: Azure SigninLogs puts ISO-3166 alpha-2 codes (e.g.
    // "JP", "US") under a `country` *name*-shaped field. Detect and
    // swap so the response shape matches user expectation
    // (`country_code` carries the code, `country_name` the full name).
    // Heuristic: 2 ASCII uppercase letters AND no preexisting code.
    let (country_code, country_name) = match (country_code, country_name) {
        (None, Some(maybe_code)) if is_iso_alpha2(&maybe_code) => (Some(maybe_code), None),
        pair => pair,
    };

    if country_code.is_none()
        && country_name.is_none()
        && city.is_none()
        && asn_str.is_none()
        && as_org.is_none()
        && isp.is_none()
    {
        return None;
    }

    let asn: Option<u32> = asn_str.and_then(|s| {
        // Accept "AS15169" or "15169".
        let s = s.trim().trim_start_matches(|c: char| !c.is_ascii_digit());
        s.split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|n| n.parse::<u32>().ok())
    });

    Some(GeoIpResult {
        country_code,
        country_name,
        city,
        asn,
        as_org,
        isp,
        is_anonymous_proxy: None,
        source: Some(GeoIpSource::DatasetMetadata),
    })
}

/// Heuristic: is `s` a 2-character ASCII uppercase token (the
/// ISO-3166 alpha-2 country code shape)?  Used by
/// `geoip_from_metadata` to detect dataset feeds that stuff the
/// 2-letter code into a name-shaped field (Azure SigninLogs being
/// the canonical offender).
fn is_iso_alpha2(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 2 && bytes.iter().all(|b| b.is_ascii_uppercase())
}

pub fn write_geoip_to_metadata(
    metadata: &mut std::collections::HashMap<String, String>,
    result: &GeoIpResult,
) {
    if let Some(ref cc) = result.country_code {
        metadata.insert("geo_country_code".into(), cc.clone());
    }
    if let Some(ref cn) = result.country_name {
        metadata.insert("geo_country".into(), cn.clone());
    }
    if let Some(ref city) = result.city {
        metadata.insert("geo_city".into(), city.clone());
    }
    if let Some(asn) = result.asn {
        metadata.insert("geo_asn".into(), format!("AS{asn}"));
    }
    if let Some(ref org) = result.as_org {
        metadata.insert("geo_as_org".into(), org.clone());
    }
    if let Some(ref isp) = result.isp {
        metadata.insert("geo_isp".into(), isp.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geoip_result_default_is_empty() {
        let r = GeoIpResult::default();
        assert!(r.country_code.is_none());
        assert!(r.asn.is_none());
    }

    #[test]
    fn write_geoip_populates_metadata() {
        let mut meta = std::collections::HashMap::new();
        let result = GeoIpResult {
            country_code: Some("US".into()),
            country_name: Some("United States".into()),
            city: Some("Mountain View".into()),
            asn: Some(15169),
            as_org: Some("Google LLC".into()),
            isp: Some("Google LLC".into()),
            is_anonymous_proxy: Some(false),
            source: Some(GeoIpSource::Maxmind),
        };
        write_geoip_to_metadata(&mut meta, &result);
        assert_eq!(meta.get("geo_country_code").unwrap(), "US");
        assert_eq!(meta.get("geo_country").unwrap(), "United States");
        assert_eq!(meta.get("geo_city").unwrap(), "Mountain View");
        assert_eq!(meta.get("geo_asn").unwrap(), "AS15169");
        assert_eq!(meta.get("geo_as_org").unwrap(), "Google LLC");
        assert_eq!(meta.get("geo_isp").unwrap(), "Google LLC");
    }

    #[test]
    fn write_geoip_skips_none_fields() {
        let mut meta = std::collections::HashMap::new();
        let result = GeoIpResult {
            country_code: Some("AR".into()),
            ..Default::default()
        };
        write_geoip_to_metadata(&mut meta, &result);
        assert_eq!(meta.len(), 1);
        assert_eq!(meta.get("geo_country_code").unwrap(), "AR");
    }
}
