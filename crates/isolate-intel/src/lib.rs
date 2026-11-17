//! isolate-intel — Intelligence engine
//!
//! Modules:
//!   pipeline  — event ingestion pipeline, fan-out to all intel plugins
//!   baseline  — behavioral baseline profiler (sliding window histograms)
//!   anomaly   — ONNX Runtime anomaly scorer (isolation forest)
//!   ioc       — IOC matching (Aho-Corasick, hash lookup, CIDR tree)
//!   feeds     — threat feed ingest (STIX/TAXII, Abuse.ch, custom)
//!   hardener  — policy auto-hardening recommender

pub mod anomaly;
pub mod baseline;
pub mod feeds;
pub mod hardener;
pub mod ioc;
pub mod pipeline;

pub use pipeline::{IntelEngine, IntelAction};
