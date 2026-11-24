//! Threat-intel enrichment pipeline — blueprint v2 §4.2, v3 §4.
//!
//! Responsibilities:
//! - Watch honeypot log files (`cowrie.json`, `dionaea.sqlite`) via the
//!   `notify` crate for new entries on write.
//! - Enrich threat data: resolve geolocation locally (MaxMind GeoLite2),
//!   query AbuseIPDB for IP reputation, query VirusTotal by SHA-256 hash only
//!   (never full-file upload by default — see AGENTS.md HC#2).
//! - All external API calls go through a dedup + token-bucket queue
//!   (`governor` crate) to stay within free-tier rate limits:
//!   - AbuseIPDB: ~1,000 checks/day
//!   - VirusTotal: ~4 requests/min
//! - Repeat IPs/hashes within 24h are served from an LRU cache, not re-queried.

#![allow(dead_code)]

use std::sync::Arc;
use std::time::Duration;

use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter};
use lru::LruCache;
use regex::Regex;
use std::sync::OnceLock;
use tokio::sync::{mpsc, Mutex};

use crate::db::DbCommand;

/// Holds the rate limiters and caches for external threat intel APIs (HC#6).
#[derive(Clone)]
pub struct ThreatIntelPipeline {
    abuseipdb_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    vt_limiter: Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>,
    db_writer: mpsc::Sender<DbCommand>,
    geoip_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    lru_cache: Arc<Mutex<LruCache<String, String>>>,
    http_client: reqwest::Client,
}

impl ThreatIntelPipeline {
    pub fn new(
        db_writer: mpsc::Sender<DbCommand>,
        geoip_reader: Option<Arc<maxminddb::Reader<Vec<u8>>>>,
    ) -> Self {
        // AbuseIPDB: 1000/day ~= 1 request every ~86 seconds.
        // For testing/bursts, let's allow 1 per 2 seconds, bursting up to 10.
        let abuseipdb_quota = Quota::with_period(Duration::from_secs(2))
            .unwrap()
            .allow_burst(std::num::NonZeroU32::new(10).unwrap());

        // VirusTotal: 4 requests per minute (1 per 15 seconds)
        let vt_quota = Quota::with_period(Duration::from_secs(15))
            .unwrap()
            .allow_burst(std::num::NonZeroU32::new(4).unwrap());

        let http_client = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            abuseipdb_limiter: Arc::new(RateLimiter::direct(abuseipdb_quota)),
            vt_limiter: Arc::new(RateLimiter::direct(vt_quota)),
            db_writer,
            geoip_reader,
            lru_cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(1000).unwrap(),
            ))),
            http_client,
        }
    }

    /// Create a session and return its ID.
    pub async fn get_or_create_session(
        &self,
        container_id: String,
        source_ip: String,
    ) -> Result<i64, String> {
        let (tx, rx) = tokio::sync::oneshot::channel();

        let mut geo_lat = None;
        let mut geo_lon = None;
        let mut geo_country = None;
        let mut geo_city = None;

        if let Some(ref reader) = self.geoip_reader {
            if let Ok(ip_addr) = source_ip.parse::<std::net::IpAddr>() {
                if let Ok(city_record) = reader.lookup::<maxminddb::geoip2::City>(ip_addr) {
                    if let Some(location) = city_record.location {
                        geo_lat = location.latitude;
                        geo_lon = location.longitude;
                    }
                    if let Some(country) = city_record.country {
                        if let Some(iso_code) = country.iso_code {
                            geo_country = Some(iso_code.to_string());
                        }
                    }
                    if let Some(city) = city_record.city {
                        if let Some(names) = city.names {
                            if let Some(en_name) = names.get("en") {
                                geo_city = Some(en_name.to_string());
                            }
                        }
                    }
                }
            }
        }

        let _ = self
            .db_writer
            .send(DbCommand::InsertSession {
                container_id,
                source_ip,
                source_port: None,
                protocol: None,
                geo_country,
                geo_city,
                geo_lat,
                geo_lon,
                reply: tx,
            })
            .await;

        rx.await.map_err(|e| e.to_string())?
    }

    /// Process a new raw event from a honeypot.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_event(
        &self,
        session_id: i64,
        container_id: String,
        event_type: String,
        source_ip: Option<String>,
        attack_vector: Option<String>,
        raw_data: Option<String>,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> Result<(), String> {
        // 1. Enrich with Threat Intel if source_ip is present (best-effort; never abort event logging)
        if let Some(ref ip) = source_ip {
            let _ = self.enrich_ip(ip, db_read).await;
        }

        // 2. Map MITRE ATT&CK TTP based on event_type
        let mitre_ttp = match event_type.as_str() {
            "cowrie.login.failed" => Some("T1110 Bruteforce".to_string()),
            "cowrie.login.success" => Some("T1078 Valid Accounts".to_string()),
            "cowrie.command.input" => Some("T1059 Command and Scripting Interpreter".to_string()),
            "cowrie.session.file_download" => Some("T1105 Ingress Tool Transfer".to_string()),
            "cowrie.session.file_upload" => {
                Some("T1048 Exfiltration Over Alternative Protocol".to_string())
            }
            "cowrie.client.version" => Some("T1046 Network Service Discovery".to_string()),
            s if s.contains("endlessh") => Some("T1046 Network Service Discovery".to_string()),
            s if s.contains("mailoney") => {
                Some("T1071.003 Mail Protocols (SMTP Relay)".to_string())
            }
            s if s.contains("conpot") => Some("T0855 Unauthorized Command Message".to_string()),
            s if s.contains("elasticpot") => {
                Some("T1190 Exploit Public-Facing Application".to_string())
            }
            s if s.contains("smb") => Some("T1021.002 SMB/Windows Admin Shares".to_string()),
            s if s.contains("credentials") => Some("T1110 Bruteforce".to_string()),
            s if s.contains("dionaea") => {
                Some("T1190 Exploit Public-Facing Application".to_string())
            }
            _ => None,
        };

        // 2.5 Extract Indicators of Compromise (IoC)
        if event_type == "cowrie.command.input" {
            if let Some(ref data) = raw_data {
                static URL_REGEX: OnceLock<Regex> = OnceLock::new();
                static IP_REGEX: OnceLock<Regex> = OnceLock::new();

                let url_re = URL_REGEX.get_or_init(|| {
                    Regex::new(r"(?i)\b(?:https?|ftp|tftp)://[^\s/$.?#].[^\s]*\b").unwrap()
                });
                // HIGH-2 fix: strict regex requiring valid IPv4 octets (0-255)
                let ip_re = IP_REGEX.get_or_init(|| {
                    Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b").unwrap()
                });

                // Extract URLs
                for cap in url_re.captures_iter(data) {
                    if let Some(matched) = cap.get(0) {
                        let _ = self
                            .db_writer
                            .send(DbCommand::InsertIoc {
                                session_id: Some(session_id),
                                container_id: container_id.clone(),
                                ioc_type: "URL".to_string(),
                                ioc_value: matched.as_str().to_string(),
                            })
                            .await;
                    }
                }

                // Extract IPs
                for cap in ip_re.captures_iter(data) {
                    if let Some(matched) = cap.get(0) {
                        let ip_str = matched.as_str();

                        // Skip private, loopback, local, multicast, broadcast, and reserved testnet IPs
                        if let Ok(std::net::IpAddr::V4(ipv4)) = ip_str.parse::<std::net::IpAddr>() {
                            let octets = ipv4.octets();
                            if ipv4.is_private()
                                || ipv4.is_loopback()
                                || ipv4.is_link_local()
                                || ipv4.is_unspecified()
                                || ipv4.is_broadcast()
                                || ipv4.is_multicast()
                                || octets[0] == 0
                                || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
                            {
                                continue;
                            }
                        } else if let Ok(std::net::IpAddr::V6(ipv6)) =
                            ip_str.parse::<std::net::IpAddr>()
                        {
                            if ipv6.is_loopback() || ipv6.is_unspecified() || ipv6.is_multicast() {
                                continue;
                            }
                        } else {
                            continue; // Invalid format
                        }

                        let _ = self
                            .db_writer
                            .send(DbCommand::InsertIoc {
                                session_id: Some(session_id),
                                container_id: container_id.clone(),
                                ioc_type: "IP".to_string(),
                                ioc_value: ip_str.to_string(),
                            })
                            .await;
                    }
                }
            }
        }

        // 3. Forward to database writer
        let _ = self
            .db_writer
            .send(DbCommand::InsertEvent {
                session_id,
                container_id,
                event_type,
                source_ip,
                attack_vector,
                raw_data,
                mitre_ttp,
            })
            .await;

        Ok(())
    }

    /// Update session with fingerprinting information
    pub async fn update_fingerprint(
        &self,
        session_id: i64,
        ssh_client_version: Option<String>,
        ja3_fingerprint: Option<String>,
        tty_log_path: Option<String>,
    ) {
        let _ = self
            .db_writer
            .send(DbCommand::UpdateSessionFingerprint {
                session_id,
                ssh_client_version,
                ja3_fingerprint,
                tty_log_path,
            })
            .await;
    }

    /// Close an active session upon disconnect or log closure (MED-4).
    pub async fn close_session(&self, session_id: i64) {
        let _ = self
            .db_writer
            .send(DbCommand::CloseSession { session_id })
            .await;
    }

    /// Check cache, rate-limit, and query AbuseIPDB for an IP.
    ///
    /// HIGH-1 fix: releases the LRU Mutex before awaiting the rate limiter
    /// and HTTP request to avoid holding an async lock across network I/O.
    pub async fn enrich_ip(
        &self,
        ip: &str,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> Result<(), String> {
        let parsed_ip = ip
            .parse::<std::net::IpAddr>()
            .map_err(|_| format!("Invalid IP address: {}", ip))?;

        // Skip private, loopback, and unroutable IP addresses to avoid wasted lookups and AbuseIPDB 422 errors
        let is_unroutable = match parsed_ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_unspecified()
                    || v4.is_broadcast()
                    || v4.is_multicast()
                    || v4.is_documentation()
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()
                    || v6.is_unspecified()
                    || v6.is_multicast()
                    || v6.is_unicast_link_local()
            }
        };
        if is_unroutable {
            return Ok(());
        }

        let canonical_ip = parsed_ip.to_string();
        let cache_key = format!("ip:{}", canonical_ip);

        // Check LRU cache first — acquire and release quickly
        {
            let lru = self.lru_cache.lock().await;
            if lru.contains(&cache_key) {
                return Ok(());
            }
        }

        // Check SQLite cache (24h dedup) in a synchronous block
        if let Some(result) = self.get_cached_intel(&cache_key, db_read)? {
            let mut lru = self.lru_cache.lock().await;
            lru.put(cache_key.clone(), result);
            return Ok(());
        }

        // Not in cache — fetch API key before consuming rate-limit budget
        let api_key =
            match keyring::Entry::new("decoyops", "abuseipdb").and_then(|e| e.get_password()) {
                Ok(k) if !k.trim().is_empty() => k,
                _ => {
                    return Err("AbuseIPDB API key not configured".to_string());
                }
            };

        // Wait for rate limiter WITHOUT holding LRU lock
        self.abuseipdb_limiter.until_ready().await;

        // Make HTTP request to AbuseIPDB (without holding LRU lock)
        let resp = match self
            .http_client
            .get("https://api.abuseipdb.com/api/v2/check")
            .query(&[("ipAddress", canonical_ip.as_str())])
            .header("Key", api_key.trim())
            .header("Accept", "application/json")
            .send()
            .await
        {
            Ok(r) => {
                if !r.status().is_success() {
                    return Err(format!(
                        "AbuseIPDB request failed with status: {}",
                        r.status()
                    ));
                }
                r
            }
            Err(e) => return Err(format!("AbuseIPDB request failed: {}", e)),
        };

        let result_json = match resp.text().await {
            Ok(t) => t,
            Err(e) => return Err(format!("Failed to read AbuseIPDB response: {}", e)),
        };

        // Re-acquire lock only to store the result
        let mut lru = self.lru_cache.lock().await;
        self.save_cache("abuseipdb", &cache_key, result_json, &mut lru)
            .await;
        Ok(())
    }

    fn get_cached_intel(
        &self,
        cache_key: &str,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> Result<Option<String>, String> {
        let conn = db_read.lock().map_err(|e| e.to_string())?;
        let res = if let Ok(mut stmt) = conn.prepare(
            "SELECT result_json FROM threat_intel_cache WHERE key = ?1 AND queried_at >= datetime('now', '-1 day')",
        ) {
            stmt.query_row([cache_key], |row| row.get(0)).ok()
        } else {
            None
        };
        Ok(res)
    }

    async fn save_cache(
        &self,
        kind: &str,
        cache_key: &str,
        result_json: String,
        lru: &mut tokio::sync::MutexGuard<'_, lru::LruCache<String, String>>,
    ) {
        let _ = self
            .db_writer
            .send(DbCommand::CacheThreatIntel {
                key: cache_key.to_string(),
                kind: kind.to_string(),
                result_json: result_json.clone(),
            })
            .await;
        lru.put(cache_key.to_string(), result_json);
    }

    /// Check cache, rate-limit, and query VirusTotal for a file hash.
    ///
    /// HIGH-1 fix: same pattern — release LRU lock before network I/O.
    pub async fn enrich_hash(
        &self,
        hash: &str,
        db_read: &std::sync::Mutex<rusqlite::Connection>,
    ) -> Result<String, String> {
        let normalized_hash = hash.trim().to_ascii_lowercase();
        if !matches!(normalized_hash.len(), 32 | 40 | 64)
            || !normalized_hash.chars().all(|c| c.is_ascii_hexdigit())
        {
            return Err("Invalid hash format: expected MD5, SHA-1, or SHA-256 hex string".into());
        }

        let cache_key = format!("hash:{}", normalized_hash);

        {
            let mut lru = self.lru_cache.lock().await;
            if let Some(cached) = lru.get(&cache_key) {
                return Ok(cached.clone());
            }
        }

        if let Some(result) = self.get_cached_intel(&cache_key, db_read)? {
            let mut lru = self.lru_cache.lock().await;
            lru.put(cache_key.clone(), result.clone());
            return Ok(result);
        }

        // Fetch API key from keyring before consuming rate-limit budget
        let api_key =
            match keyring::Entry::new("decoyops", "virustotal").and_then(|e| e.get_password()) {
                Ok(k) if !k.trim().is_empty() => k,
                _ => {
                    return Err("VirusTotal API key not configured".to_string());
                }
            };

        // Wait for rate limiter WITHOUT holding LRU lock
        self.vt_limiter.until_ready().await;

        let resp = match self
            .http_client
            .get(format!(
                "https://www.virustotal.com/api/v3/files/{}",
                normalized_hash
            ))
            .header("x-apikey", api_key.trim())
            .send()
            .await
        {
            Ok(r) => {
                if !r.status().is_success() {
                    return Err(format!(
                        "VirusTotal request failed with status: {}",
                        r.status()
                    ));
                }
                r
            }
            Err(e) => return Err(format!("VirusTotal request failed: {}", e)),
        };

        let result_json = match resp.text().await {
            Ok(t) => t,
            Err(e) => return Err(format!("Failed to read VirusTotal response: {}", e)),
        };

        let vt_status = serde_json::from_str::<serde_json::Value>(&result_json)
            .ok()
            .and_then(|v| {
                v.pointer("/data/attributes/last_analysis_stats/malicious")
                    .and_then(|m| m.as_u64())
            })
            .map(|malicious| {
                if malicious > 0 {
                    "malicious".to_string()
                } else {
                    "clean".to_string()
                }
            })
            .unwrap_or_else(|| "scanned".to_string());

        let _ = self
            .db_writer
            .send(DbCommand::UpdateCapturedFileVt {
                sha256: normalized_hash,
                vt_status,
                vt_result_json: result_json.clone(),
            })
            .await;

        let mut lru = self.lru_cache.lock().await;
        self.save_cache("virustotal", &cache_key, result_json.clone(), &mut lru)
            .await;
        Ok(result_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn enrich_rejects_invalid_ip_and_hash_and_skips_private_ip() {
        let conn = crate::db::open_database(":memory:").unwrap();
        let db_read = std::sync::Mutex::new(conn);
        let (tx, _rx) = mpsc::channel(8);
        let pipeline = ThreatIntelPipeline::new(tx, None);

        assert!(pipeline
            .enrich_ip("1.2.3.4&evil=1", &db_read)
            .await
            .is_err());
        assert!(pipeline.enrich_ip("192.168.1.10", &db_read).await.is_ok());
        assert!(pipeline.enrich_ip("0.0.0.0", &db_read).await.is_ok());
        assert!(pipeline.enrich_hash("../secret", &db_read).await.is_err());
        assert!(pipeline.enrich_hash("zzzz", &db_read).await.is_err());
    }
}
