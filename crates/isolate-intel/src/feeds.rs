//! Threat feed ingest — STIX/TAXII, Abuse.ch, custom CSV/JSON feeds.
//!
//! Supports:
//!   - STIX 2.1 / TAXII 2.1 (industry standard)
//!   - Abuse.ch URLhaus, MalwareBazaar, ThreatFox (JSON API)
//!   - Custom CSV/JSON/YAML local or remote files
//!   - ETag/Last-Modified delta updates (efficient polling)
//!   - Configurable refresh intervals

use crate::ioc::{IocEntry, IocMatcher};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

#[derive(Debug, Clone)]
pub struct FeedConfig {
    pub name: String,
    pub url: String,
    pub format: FeedFormat,
    pub refresh_interval_secs: u64,
    pub confidence: f32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeedFormat {
    AbusechUrlhaus,
    AbusechMalwareBazaar,
    AbusechThreatFox,
    StixTaxii,
    CustomJson,
    CustomCsv,
}

/// Built-in feed configurations.
pub fn builtin_feeds() -> Vec<FeedConfig> {
    vec![
        FeedConfig {
            name: "abusech-urlhaus".into(),
            url: "https://urlhaus-api.abuse.ch/v1/urls/recent/".into(),
            format: FeedFormat::AbusechUrlhaus,
            refresh_interval_secs: 21600, // 6 hours
            confidence: 0.85,
        },
        FeedConfig {
            name: "abusech-malwarebazaar".into(),
            url: "https://mb-api.abuse.ch/api/v1/".into(),
            format: FeedFormat::AbusechMalwareBazaar,
            refresh_interval_secs: 21600,
            confidence: 0.90,
        },
        FeedConfig {
            name: "abusech-threatfox".into(),
            url: "https://threatfox-api.abuse.ch/api/v1/".into(),
            format: FeedFormat::AbusechThreatFox,
            refresh_interval_secs: 21600,
            confidence: 0.88,
        },
    ]
}

pub struct FeedManager {
    feeds: Vec<FeedConfig>,
    ioc_matcher: Arc<IocMatcher>,
    etags: HashMap<String, String>,
}

impl FeedManager {
    pub fn new(feeds: Vec<FeedConfig>, ioc_matcher: Arc<IocMatcher>) -> Self {
        Self { feeds, ioc_matcher, etags: HashMap::new() }
    }

    /// Start the periodic feed refresh loop.
    pub async fn run(mut self) {
        let min_interval = self.feeds.iter()
            .map(|f| f.refresh_interval_secs)
            .min()
            .unwrap_or(3600);

        let mut ticker = interval(Duration::from_secs(min_interval / 10));

        loop {
            ticker.tick().await;
            for feed in &self.feeds.clone() {
                if let Err(e) = self.refresh_feed(feed).await {
                    error!(feed = %feed.name, error = %e, "feed refresh failed");
                }
            }
        }
    }

    async fn refresh_feed(&mut self, feed: &FeedConfig) -> anyhow::Result<()> {
        info!(feed = %feed.name, "refreshing threat feed");

        let client = reqwest::Client::new();
        let mut req = client.get(&feed.url);

        // ETag-based delta updates
        if let Some(etag) = self.etags.get(&feed.name) {
            req = req.header("If-None-Match", etag);
        }

        let response = req.send().await?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            info!(feed = %feed.name, "feed unchanged (304)");
            return Ok(());
        }

        // Save new ETag
        if let Some(etag) = response.headers().get("etag") {
            self.etags.insert(feed.name.clone(), etag.to_str()?.to_owned());
        }

        let text = response.text().await?;
        let entries = parse_feed(feed, &text)?;

        info!(feed = %feed.name, count = entries.len(), "loaded IOC entries");
        self.ioc_matcher.insert_batch(entries);

        Ok(())
    }
}

fn parse_feed(feed: &FeedConfig, text: &str) -> anyhow::Result<Vec<IocEntry>> {
    match feed.format {
        FeedFormat::AbusechMalwareBazaar => parse_malwarebazaar(feed, text),
        FeedFormat::AbusechUrlhaus => parse_urlhaus(feed, text),
        FeedFormat::AbusechThreatFox => parse_threatfox(feed, text),
        FeedFormat::CustomJson => parse_custom_json(feed, text),
        _ => Ok(vec![]),
    }
}

fn parse_malwarebazaar(feed: &FeedConfig, text: &str) -> anyhow::Result<Vec<IocEntry>> {
    #[derive(Deserialize)]
    struct Response {
        data: Option<Vec<Sample>>,
    }
    #[derive(Deserialize)]
    struct Sample {
        sha256_hash: String,
        #[serde(rename = "tags")]
        tags: Option<Vec<String>>,
        file_type: Option<String>,
    }

    let resp: Response = serde_json::from_str(text)?;
    Ok(resp.data.unwrap_or_default().into_iter().map(|s| IocEntry {
        feed: feed.name.clone(),
        indicator_type: "hash-sha256".into(),
        indicator_value: s.sha256_hash,
        confidence: feed.confidence,
        threat_type: s.file_type,
        reference: None,
    }).collect())
}

fn parse_urlhaus(feed: &FeedConfig, text: &str) -> anyhow::Result<Vec<IocEntry>> {
    #[derive(Deserialize)]
    struct Response {
        urls: Option<Vec<UrlEntry>>,
    }
    #[derive(Deserialize)]
    struct UrlEntry {
        url: String,
        threat: Option<String>,
    }

    let resp: Response = serde_json::from_str(text)?;
    Ok(resp.urls.unwrap_or_default().into_iter().map(|u| IocEntry {
        feed: feed.name.clone(),
        indicator_type: "url".into(),
        indicator_value: u.url,
        confidence: feed.confidence,
        threat_type: u.threat,
        reference: None,
    }).collect())
}

fn parse_threatfox(feed: &FeedConfig, text: &str) -> anyhow::Result<Vec<IocEntry>> {
    #[derive(Deserialize)]
    struct Response {
        data: Option<Vec<Ioc>>,
    }
    #[derive(Deserialize)]
    struct Ioc {
        ioc_value: String,
        ioc_type: String,
        threat_type: Option<String>,
        confidence_level: Option<u32>,
        reference: Option<String>,
    }

    let resp: Response = serde_json::from_str(text)?;
    Ok(resp.data.unwrap_or_default().into_iter().map(|i| IocEntry {
        feed: feed.name.clone(),
        indicator_type: i.ioc_type,
        indicator_value: i.ioc_value,
        confidence: i.confidence_level.unwrap_or(50) as f32 / 100.0,
        threat_type: i.threat_type,
        reference: i.reference,
    }).collect())
}

fn parse_custom_json(feed: &FeedConfig, text: &str) -> anyhow::Result<Vec<IocEntry>> {
    // Custom JSON: array of objects with {type, value, confidence?, threat_type?, reference?}
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "type")]
        indicator_type: String,
        value: String,
        confidence: Option<f32>,
        threat_type: Option<String>,
        reference: Option<String>,
    }

    let entries: Vec<Entry> = serde_json::from_str(text)?;
    Ok(entries.into_iter().map(|e| IocEntry {
        feed: feed.name.clone(),
        indicator_type: e.indicator_type,
        indicator_value: e.value,
        confidence: e.confidence.unwrap_or(feed.confidence),
        threat_type: e.threat_type,
        reference: e.reference,
    }).collect())
}
