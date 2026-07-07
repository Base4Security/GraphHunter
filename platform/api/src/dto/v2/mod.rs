//! DTO v2 — breaking-change namespace. Empty at `platform/api` v1.0.0.
//!
//! When a request/response shape needs to change in a way that would
//! break existing clients, add a `v2` variant here and leave the v1
//! module untouched. Clients opt into v2 per endpoint; the router
//! dispatches by path (e.g. `/v2/hunt/run`) or by `Accept-Version`
//! header.
//!
//! **Do not** re-export v1 types from here; callers should be explicit
//! about the version they consume.
