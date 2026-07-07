//! Dead-letter queue API operations: list, reingest, purge.
//!
//! The on-disk store lives in `graph_hunter_core::dlq` — this layer
//! is just the session-scoped filter + paging + reingest orchestration.
//!
//! Reingest semantics: take a set of DLQ ids, group by their original
//! `dataset_id`, write the raw events out to a temp file per dataset,
//! and replay through `load_data_with_config` using the dataset's
//! *current* FieldConfig (the user is expected to have fixed the
//! mapping between the original failure and the retry). Entries whose
//! dataset no longer exists, or that were ingested with no FieldConfig,
//! are returned as `failed` — they stay in the DLQ for a follow-up.

use std::collections::{HashMap, HashSet};
use std::io::Write;

use graph_hunter_core::dlq::{DeadLetter, FailureKind};

use crate::dto::dlq::{
    ListDeadLettersRequest, ListDeadLettersResponse, PurgeDeadLettersRequest,
    PurgeDeadLettersResponse, ReingestDeadLetterRequest, ReingestDeadLetterResponse,
    ReingestFailure,
};
use crate::dto::ingestion::LoadDataWithConfigRequest;
use crate::{ApiError, ApiResult, GraphHunterApi};

const DEFAULT_PAGE_SIZE: usize = 100;
const MAX_PAGE_SIZE: usize = 1000;

impl GraphHunterApi {
    /// Paginated view of dead-letter entries with optional filters.
    /// Returns an empty list when the DLQ store is unconfigured —
    /// consistent with the drift store's graceful-degradation contract.
    pub fn list_dead_letters(
        &self,
        req: ListDeadLettersRequest,
    ) -> ApiResult<ListDeadLettersResponse> {
        self.resolve_session(req.session.as_ref())?;
        let Some(store) = self.dlq_store() else {
            return Ok(ListDeadLettersResponse {
                entries: Vec::new(),
                total: 0,
                has_more: false,
            });
        };
        let entries = store
            .list_all()
            .map_err(|e| ApiError::Internal(format!("dlq list_all: {e}")))?;
        let filtered: Vec<DeadLetter> = entries
            .into_iter()
            .filter(|e| matches_filter(e, req.dataset_id.as_deref(), req.failure_kind))
            .collect();
        let total = filtered.len();
        let offset = req.offset.unwrap_or(0);
        let limit = req
            .limit
            .unwrap_or(DEFAULT_PAGE_SIZE)
            .clamp(1, MAX_PAGE_SIZE);
        let end = offset.saturating_add(limit).min(total);
        let page: Vec<DeadLetter> = if offset >= total {
            Vec::new()
        } else {
            filtered[offset..end].to_vec()
        };
        let has_more = end < total;
        Ok(ListDeadLettersResponse {
            entries: page,
            total,
            has_more,
        })
    }

    /// Reingest a specific set of DLQ entries against their datasets'
    /// current FieldConfigs. Successful rows are removed from the DLQ;
    /// rows whose dataset is missing / unmapped come back in `failed`.
    pub fn reingest_dead_letter(
        &self,
        req: ReingestDeadLetterRequest,
    ) -> ApiResult<ReingestDeadLetterResponse> {
        let session = self.resolve_session(req.session.as_ref())?;
        let requested: HashSet<String> = req.dlq_ids.iter().cloned().collect();
        if requested.is_empty() {
            return Ok(ReingestDeadLetterResponse {
                reingested: Vec::new(),
                not_found: Vec::new(),
                failed: Vec::new(),
            });
        }
        let Some(store) = self.dlq_store() else {
            return Ok(ReingestDeadLetterResponse {
                reingested: Vec::new(),
                not_found: req.dlq_ids,
                failed: Vec::new(),
            });
        };

        let all = store
            .list_all()
            .map_err(|e| ApiError::Internal(format!("dlq list_all: {e}")))?;

        // Bucket the matching entries by dataset_id.
        let mut by_dataset: HashMap<String, Vec<DeadLetter>> = HashMap::new();
        let mut unmatched = requested.clone();
        let mut failed: Vec<ReingestFailure> = Vec::new();
        let mut untagged_ids: Vec<String> = Vec::new();
        for entry in all {
            if !requested.contains(&entry.dlq_id) {
                continue;
            }
            unmatched.remove(&entry.dlq_id);
            match entry.dataset_id.clone() {
                Some(ds) => by_dataset.entry(ds).or_default().push(entry),
                None => untagged_ids.push(entry.dlq_id.clone()),
            }
        }
        for id in untagged_ids {
            failed.push(ReingestFailure {
                dlq_id: id,
                reason: "entry has no dataset_id; cannot derive a FieldConfig for reingest".into(),
            });
        }

        let mut reingested: Vec<String> = Vec::new();
        for (dataset_id, entries) in by_dataset {
            // Find the dataset's current FieldConfig.
            let fc = {
                let datasets = session
                    .datasets
                    .read()
                    .map_err(|e| ApiError::Internal(format!("datasets lock poisoned: {e}")))?;
                datasets
                    .iter()
                    .find(|d| d.id == dataset_id)
                    .and_then(|d| d.field_config.clone())
            };
            let Some(field_config) = fc else {
                for e in entries {
                    failed.push(ReingestFailure {
                        dlq_id: e.dlq_id,
                        reason: format!(
                            "dataset '{dataset_id}' has no FieldConfig; \
                             promote one via agentic_review_approve before retrying"
                        ),
                    });
                }
                continue;
            };

            // Write the raw events to a temp file and replay.
            let tmp = match tempfile::NamedTempFile::new() {
                Ok(t) => t,
                Err(e) => {
                    for entry in entries {
                        failed.push(ReingestFailure {
                            dlq_id: entry.dlq_id,
                            reason: format!("tempfile: {e}"),
                        });
                    }
                    continue;
                }
            };
            {
                let mut w = tmp.as_file();
                let mut wrote_any = false;
                let mut write_err: Option<String> = None;
                for e in &entries {
                    if let Err(err) = writeln!(w, "{}", e.raw_event) {
                        write_err = Some(err.to_string());
                        break;
                    }
                    wrote_any = true;
                }
                if let Some(err) = write_err {
                    for e in &entries {
                        failed.push(ReingestFailure {
                            dlq_id: e.dlq_id.clone(),
                            reason: format!("write tmp: {err}"),
                        });
                    }
                    continue;
                }
                if !wrote_any {
                    continue;
                }
            }

            let path = tmp.path().to_string_lossy().into_owned();
            let replay = self.load_data_with_config(LoadDataWithConfigRequest {
                session: None,
                path,
                config: field_config,
            });
            match replay {
                Ok(_) => {
                    for e in entries {
                        reingested.push(e.dlq_id);
                    }
                }
                Err(err) => {
                    let reason = err.to_string();
                    for e in entries {
                        failed.push(ReingestFailure {
                            dlq_id: e.dlq_id,
                            reason: reason.clone(),
                        });
                    }
                }
            }
        }

        // Consume the successfully-reingested ids from the DLQ.
        if !reingested.is_empty() {
            let set: HashSet<String> = reingested.iter().cloned().collect();
            store
                .consume(&set)
                .map_err(|e| ApiError::Internal(format!("dlq consume: {e}")))?;
        }

        let not_found: Vec<String> = unmatched.into_iter().collect();
        Ok(ReingestDeadLetterResponse {
            reingested,
            not_found,
            failed,
        })
    }

    /// Bulk-consume DLQ entries. Without `all=true`, filters must be
    /// supplied or the op returns `InvalidInput` — guards against
    /// accidental full wipes through an empty-filter payload.
    pub fn purge_dead_letters(
        &self,
        req: PurgeDeadLettersRequest,
    ) -> ApiResult<PurgeDeadLettersResponse> {
        self.resolve_session(req.session.as_ref())?;
        if !req.all && req.dataset_id.is_none() && req.failure_kind.is_none() {
            return Err(ApiError::InvalidInput(
                "purge requires `all=true` or at least one of `dataset_id` / `failure_kind`".into(),
            ));
        }
        let Some(store) = self.dlq_store() else {
            return Ok(PurgeDeadLettersResponse { removed: 0 });
        };
        if req.all {
            let removed = store
                .pending_count()
                .map_err(|e| ApiError::Internal(format!("dlq pending_count: {e}")))?;
            store
                .clear()
                .map_err(|e| ApiError::Internal(format!("dlq clear: {e}")))?;
            return Ok(PurgeDeadLettersResponse { removed });
        }
        let all = store
            .list_all()
            .map_err(|e| ApiError::Internal(format!("dlq list_all: {e}")))?;
        let ids: HashSet<String> = all
            .into_iter()
            .filter(|e| matches_filter(e, req.dataset_id.as_deref(), req.failure_kind))
            .map(|e| e.dlq_id)
            .collect();
        let removed = store
            .consume(&ids)
            .map_err(|e| ApiError::Internal(format!("dlq consume: {e}")))?;
        Ok(PurgeDeadLettersResponse { removed })
    }

    /// Push a dead-letter to the configured store. No-op when the
    /// store is unconfigured (tests, headless) — matches the drift
    /// store's contract.
    pub fn record_dead_letter(&self, entry: DeadLetter) {
        let Some(store) = self.dlq_store() else {
            return;
        };
        if let Err(e) = store.append(entry) {
            tracing::warn!("dlq append failed: {e}");
        }
    }

    /// Drain a `ParseStats.skipped_samples` into the DLQ. Called by
    /// the ingestion ops after every `parse_with_stats` so parse
    /// failures stop being silently dropped. No-op when the DLQ
    /// store is unconfigured.
    pub fn record_parse_skips(
        &self,
        dataset_id: &str,
        source_id: Option<&str>,
        stats: &graph_hunter_core::parser::ParseStats,
    ) {
        if stats.skipped_samples.is_empty() {
            return;
        }
        let Some(store) = self.dlq_store() else {
            return;
        };
        let ts = crate::util::now_secs();
        for (raw, reason) in &stats.skipped_samples {
            let entry = DeadLetter {
                dlq_id: String::new(),
                raw_event: raw.clone(),
                failure_kind: FailureKind::ParseFailure,
                reason: reason.clone(),
                dataset_id: Some(dataset_id.to_string()),
                source_id: source_id.map(str::to_string),
                ts_received: ts,
            };
            if let Err(e) = store.append(entry) {
                tracing::warn!("dlq append (parse-skip) failed: {e}");
                break;
            }
        }
    }

    /// Drain a `try_parse` Err stream into the DLQ (RH-P1-012).
    ///
    /// Companion to [`Self::record_parse_skips`] for parsers that have
    /// been migrated to `LogParser::try_parse`. Each `ParseError` from
    /// the parser's per-row Result stream is appended to the DLQ with
    /// the variant's `Display` rendering as the reason and the variant
    /// tag stamped onto `raw_event` so the UI can filter by error class.
    ///
    /// No-op when the DLQ store is unconfigured or when `errors` is
    /// empty. The break-on-store-failure semantics match
    /// `record_parse_skips` — one failed append stops the drain so we
    /// don't hammer a broken store with thousands of subsequent appends.
    pub fn record_parse_errors(
        &self,
        dataset_id: &str,
        source_id: Option<&str>,
        errors: &[graph_hunter_core::parser::ParseError],
    ) {
        if errors.is_empty() {
            return;
        }
        let Some(store) = self.dlq_store() else {
            return;
        };
        let ts = crate::util::now_secs();
        for err in errors {
            let variant_tag = match err {
                graph_hunter_core::parser::ParseError::MalformedRow { .. } => "MalformedRow",
                graph_hunter_core::parser::ParseError::FieldType { .. } => "FieldType",
                graph_hunter_core::parser::ParseError::MissingField(_) => "MissingField",
                graph_hunter_core::parser::ParseError::Encoding(_) => "Encoding",
                graph_hunter_core::parser::ParseError::SourceSpecific(_) => "SourceSpecific",
            };
            let entry = DeadLetter {
                dlq_id: String::new(),
                // Stamp the variant tag onto raw_event so DLQ consumers can
                // filter by class without re-parsing the reason string.
                raw_event: format!("[try_parse::{}]", variant_tag),
                failure_kind: FailureKind::ParseFailure,
                reason: err.to_string(),
                dataset_id: Some(dataset_id.to_string()),
                source_id: source_id.map(str::to_string),
                ts_received: ts,
            };
            if let Err(e) = store.append(entry) {
                tracing::warn!("dlq append (try_parse error) failed: {e}");
                break;
            }
        }
    }
}

fn matches_filter(
    e: &DeadLetter,
    dataset_id: Option<&str>,
    failure_kind: Option<FailureKind>,
) -> bool {
    if let Some(ds) = dataset_id {
        if e.dataset_id.as_deref() != Some(ds) {
            return false;
        }
    }
    if let Some(kind) = failure_kind {
        if e.failure_kind != kind {
            return false;
        }
    }
    true
}

// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::session::CreateSessionRequest;
    use crate::state::DatasetInfo;
    use graph_hunter_core::dlq::DlqStore;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn api_with_dlq(tmp: &TempDir) -> GraphHunterApi {
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("dlq-test".into()),
        })
        .expect("create_session");
        let store = Arc::new(DlqStore::open(tmp.path()).unwrap());
        *api.dlq_store_handle().lock().unwrap() = Some(store);
        api
    }

    fn mk_entry(raw: &str, ds: Option<&str>, kind: FailureKind) -> DeadLetter {
        DeadLetter {
            dlq_id: String::new(),
            raw_event: raw.into(),
            failure_kind: kind,
            reason: "test".into(),
            dataset_id: ds.map(str::to_string),
            source_id: Some("src".into()),
            ts_received: 0,
        }
    }

    #[test]
    fn list_respects_dataset_filter() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        api.record_dead_letter(mk_entry("a", Some("ds-1"), FailureKind::ParseFailure));
        api.record_dead_letter(mk_entry("b", Some("ds-2"), FailureKind::ParseFailure));
        let resp = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: Some("ds-1".into()),
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(resp.total, 1);
        assert_eq!(resp.entries[0].raw_event, "a");
    }

    #[test]
    fn list_without_store_returns_empty() {
        // No DLQ store configured — ops must degrade gracefully.
        let api = GraphHunterApi::new_noop();
        api.create_session(CreateSessionRequest {
            name: Some("t".into()),
        })
        .unwrap();
        let resp = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: None,
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(resp.total, 0);
        assert!(resp.entries.is_empty());
    }

    #[test]
    fn purge_all_wipes_every_shard() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        for i in 0..3 {
            api.record_dead_letter(mk_entry(
                &format!("r-{i}"),
                Some("ds-1"),
                FailureKind::ParseFailure,
            ));
        }
        let resp = api
            .purge_dead_letters(PurgeDeadLettersRequest {
                session: None,
                all: true,
                dataset_id: None,
                failure_kind: None,
            })
            .unwrap();
        assert_eq!(resp.removed, 3);
        let remaining = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: None,
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(remaining.total, 0);
    }

    #[test]
    fn purge_rejects_empty_filter_without_all_flag() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        let err = api
            .purge_dead_letters(PurgeDeadLettersRequest {
                session: None,
                all: false,
                dataset_id: None,
                failure_kind: None,
            })
            .expect_err("must reject empty filter");
        assert!(matches!(err, ApiError::InvalidInput(_)));
    }

    #[test]
    fn reingest_flags_missing_dataset_as_failed() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        let _ = api.record_dead_letter(mk_entry("row", Some("ds-gone"), FailureKind::ParseFailure));
        // No dataset in the session — reingest must fail gracefully.
        let list = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: None,
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        let id = list.entries[0].dlq_id.clone();
        let resp = api
            .reingest_dead_letter(ReingestDeadLetterRequest {
                session: None,
                dlq_ids: vec![id.clone()],
            })
            .unwrap();
        assert!(resp.reingested.is_empty());
        assert_eq!(resp.failed.len(), 1);
        assert_eq!(resp.failed[0].dlq_id, id);
        assert!(resp.failed[0].reason.contains("ds-gone"));
    }

    #[test]
    fn reingest_reports_not_found_for_unknown_ids() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        let resp = api
            .reingest_dead_letter(ReingestDeadLetterRequest {
                session: None,
                dlq_ids: vec!["no-such-id".into()],
            })
            .unwrap();
        assert_eq!(resp.not_found.len(), 1);
        assert_eq!(resp.not_found[0], "no-such-id");
    }

    #[test]
    fn record_parse_errors_writes_each_variant_to_dlq() {
        // RH-P1-012: record_parse_errors must persist each ParseError from
        // a try_parse stream as a DLQ entry, stamped with its variant tag.
        use graph_hunter_core::parser::ParseError;
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);

        let errors = vec![
            ParseError::MalformedRow {
                line: 3,
                reason: "expected 5 tokens, got 2".into(),
            },
            ParseError::Encoding("not utf8".into()),
            ParseError::MissingField("timestamp".into()),
        ];
        api.record_parse_errors("ds-rh-p1-012", Some("iis_w3c"), &errors);

        let resp = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: Some("ds-rh-p1-012".into()),
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(resp.total, 3);

        // Verify variant tags were stamped onto raw_event.
        let raws: Vec<String> = resp.entries.iter().map(|e| e.raw_event.clone()).collect();
        assert!(raws.iter().any(|r| r.contains("MalformedRow")), "{:?}", raws);
        assert!(raws.iter().any(|r| r.contains("Encoding")), "{:?}", raws);
        assert!(raws.iter().any(|r| r.contains("MissingField")), "{:?}", raws);

        // All entries route through ParseFailure (not InsertFailure).
        for e in &resp.entries {
            assert_eq!(e.failure_kind, FailureKind::ParseFailure);
            assert_eq!(e.source_id.as_deref(), Some("iis_w3c"));
        }
    }

    #[test]
    fn record_parse_errors_empty_input_is_noop() {
        let tmp = TempDir::new().unwrap();
        let api = api_with_dlq(&tmp);
        api.record_parse_errors("ds-noop", None, &[]);
        let resp = api
            .list_dead_letters(ListDeadLettersRequest {
                session: None,
                dataset_id: Some("ds-noop".into()),
                failure_kind: None,
                offset: None,
                limit: None,
            })
            .unwrap();
        assert_eq!(resp.total, 0);
    }

    // Silence the unused-dataset warning for the DatasetInfo type only
    // ever referenced from the live ingestion paths.
    #[allow(dead_code)]
    fn _referenced_types() -> DatasetInfo {
        unimplemented!()
    }
}
