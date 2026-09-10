use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::Deserialize;
use std::time::Instant;

const NVD_API_URL: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const DEFAULT_USER_AGENT: &str = "DREAD/1.0 (Rust engine)";

#[derive(Debug, Deserialize)]
struct NvdResponse {
    #[serde(default)]
    vulnerabilities: Vec<NvdVulnerability>,
    #[serde(default)]
    totalResults: u64,
    #[serde(default)]
    resultsPerPage: u64,
    #[serde(default)]
    format: String,
}

#[derive(Debug, Deserialize)]
struct NvdVulnerability {
    cve: NvdCveItem,
}

#[derive(Debug, Deserialize)]
struct NvdCveItem {
    id: Option<String>,
    #[serde(default)]
    descriptions: Vec<NvdDescription>,
    #[serde(default)]
    metrics: NvdMetrics,
    #[serde(default)]
    configurations: Vec<NvdConfiguration>,
    #[serde(default)]
    references: Vec<NvdReference>,
    published: Option<String>,
    lastModified: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct NvdMetrics {
    #[serde(default)]
    cvssMetricV31: Vec<NvdMetric>,
    #[serde(default)]
    cvssMetricV30: Vec<NvdMetric>,
    #[serde(default)]
    cvssMetricV2: Vec<NvdMetric>,
}

#[derive(Debug, Deserialize)]
struct NvdMetric {
    cvssData: Option<NvdCvssData>,
    baseSeverity: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdCvssData {
    baseScore: Option<f64>,
    vectorString: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdConfiguration {
    #[serde(default)]
    nodes: Vec<NvdNode>,
}

#[derive(Debug, Deserialize)]
struct NvdNode {
    #[serde(default)]
    cpeMatch: Vec<NvdCpeMatch>,
}

#[derive(Debug, Deserialize)]
struct NvdCpeMatch {
    vulnerable: Option<bool>,
    criteria: Option<String>,
    versionStartIncluding: Option<String>,
    versionEndIncluding: Option<String>,
    versionStartExcluding: Option<String>,
    versionEndExcluding: Option<String>,
}

#[derive(Debug, Deserialize)]
struct NvdReference {
    url: Option<String>,
    source: Option<String>,
    tags: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct NvdDescription {
    lang: Option<String>,
    value: Option<String>,
}

pub struct CveSyncConfig {
    pub db_path: String,
    pub mode: SyncMode,
    pub api_key: Option<String>,
    pub batch_size: u64,
}

pub enum SyncMode {
    Full,
    Incremental,
    Window { days: u64 },
    Years { years: u64 },
}

fn open_db(path: &str) -> Result<Connection> {
    let conn = Connection::open(path).context("failed to open CVE database")?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
    Ok(conn)
}

fn ensure_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS cve_entries (
            cve_id TEXT PRIMARY KEY,
            description TEXT NOT NULL,
            severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low')),
            cvss_score REAL CHECK(cvss_score >= 0 AND cvss_score <= 10),
            cvss_vector TEXT,
            published_date TEXT,
            last_modified TEXT,
            \"references\" TEXT
        );
        CREATE TABLE IF NOT EXISTS cve_products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT REFERENCES cve_entries(cve_id),
            vendor TEXT,
            product TEXT NOT NULL,
            version_start TEXT,
            version_end TEXT,
            version_start_including BOOLEAN DEFAULT 1,
            version_end_including BOOLEAN DEFAULT 1,
            UNIQUE(cve_id, vendor, product, version_start, version_end)
        );
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_entries(severity);
        CREATE INDEX IF NOT EXISTS idx_cve_cvss ON cve_entries(cvss_score);
        CREATE INDEX IF NOT EXISTS idx_product_lookup ON cve_products(vendor, product);
        CREATE INDEX IF NOT EXISTS idx_product_version ON cve_products(product, version_start, version_end);
        ",
    )?;
    Ok(())
}

fn extract_severity(metrics: &NvdMetrics, score: Option<f64>) -> Option<String> {
    let raw = if !metrics.cvssMetricV31.is_empty() {
        metrics.cvssMetricV31[0].baseSeverity.clone()
    } else if !metrics.cvssMetricV30.is_empty() {
        metrics.cvssMetricV30[0].baseSeverity.clone()
    } else if !metrics.cvssMetricV2.is_empty() {
        metrics.cvssMetricV2[0].baseSeverity.clone()
    } else {
        None
    };

    if let Some(s) = raw {
        let s = s.to_lowercase();
        match s.as_str() {
            "critical" | "high" | "medium" | "low" => return Some(s),
            "moderate" => return Some("medium".to_string()),
            _ => {}
        }
    }

    if let Some(sc) = score {
        if sc >= 9.0 {
            return Some("critical".to_string());
        }
        if sc >= 7.0 {
            return Some("high".to_string());
        }
        if sc >= 4.0 {
            return Some("medium".to_string());
        }
        return Some("low".to_string());
    }
    None
}

fn extract_cvss(metrics: &NvdMetrics) -> (Option<f64>, Option<String>) {
    if !metrics.cvssMetricV31.is_empty() {
        if let Some(ref d) = metrics.cvssMetricV31[0].cvssData {
            return (d.baseScore, d.vectorString.clone());
        }
    }
    if !metrics.cvssMetricV30.is_empty() {
        if let Some(ref d) = metrics.cvssMetricV30[0].cvssData {
            return (d.baseScore, d.vectorString.clone());
        }
    }
    if !metrics.cvssMetricV2.is_empty() {
        if let Some(ref d) = metrics.cvssMetricV2[0].cvssData {
            return (d.baseScore, d.vectorString.clone());
        }
    }
    (None, None)
}

fn get_description(descriptions: &[NvdDescription]) -> String {
    for d in descriptions {
        if d.lang.as_deref() == Some("en") {
            return d.value.clone().unwrap_or_default();
        }
    }
    descriptions
        .first()
        .and_then(|d| d.value.clone())
        .unwrap_or_default()
}

fn get_references(refs: &[NvdReference]) -> String {
    let urls: Vec<&str> = refs.iter().filter_map(|r| r.url.as_deref()).collect();
    serde_json::to_string(&urls).unwrap_or_else(|_| "[]".to_string())
}

fn extract_products(cve_id: &str, configurations: &[NvdConfiguration]) -> Vec<(String, String, String, String, String)> {
    let mut products = Vec::new();
    for config in configurations {
        for node in &config.nodes {
            for cpem in &node.cpeMatch {
                if !cpem.vulnerable.unwrap_or(false) {
                    continue;
                }
                let criteria = match cpem.criteria {
                    Some(ref c) => c,
                    None => continue,
                };
                let parts: Vec<&str> = criteria.split(':').collect();
                if parts.len() < 5 {
                    continue;
                }
                let vendor = parts.get(3).unwrap_or(&"").to_lowercase();
                let product = parts.get(4).unwrap_or(&"").to_lowercase();
                let version = parts.get(5).unwrap_or(&"*").to_lowercase();

                let version_start = cpem
                    .versionStartIncluding
                    .clone()
                    .or_else(|| {
                        if version != "*" { Some(version.clone()) } else { None }
                    })
                    .unwrap_or_default();
                let version_end = cpem
                    .versionEndIncluding
                    .clone()
                    .or_else(|| {
                        if version != "*" { Some(version.clone()) } else { None }
                    })
                    .unwrap_or_default();

                products.push((vendor, product, version_start, version_end, cve_id.to_string()));
            }
        }
    }
    products
}

pub async fn sync_cves(config: CveSyncConfig) -> Result<(u64, u64)> {
    let start = Instant::now();
    let conn = open_db(&config.db_path)?;
    ensure_schema(&conn)?;

    let mut params_vec: Vec<(&str, String)> = vec![("resultsPerPage", "2000".to_string())];
    let mut start_index: u64 = 0;

    match config.mode {
        SyncMode::Full => {
            eprintln!("[*] Full NVD corpus sync");
        }
        SyncMode::Incremental => {
            // Read last_modified from metadata
            if let Ok(last_mod) = conn.query_row(
                "SELECT value FROM metadata WHERE key = 'last_modified'",
                [],
                |row| row.get::<_, String>(0),
            ) {
                params_vec.push(("lastModStartDate", last_mod));
                let now = Utc::now().format("%Y-%m-%dT%H:%M:%S.000").to_string();
                params_vec.push(("lastModEndDate", now));
                eprintln!("[*] Incremental CVE update (modified since last cursor)");
            } else {
                eprintln!("[!] No last_modified cursor found, falling back to 30-day window");
                let end = Utc::now();
                let start_dt = end - chrono::Duration::days(30);
                params_vec.push(("pubStartDate", start_dt.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
                params_vec.push(("pubEndDate", end.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
            }
        }
        SyncMode::Window { days } => {
            let end = Utc::now();
            let start_dt = end - chrono::Duration::days(days as i64);
            params_vec.push(("pubStartDate", start_dt.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
            params_vec.push(("pubEndDate", end.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
            eprintln!("[*] Windowed update: CVEs published in last {days} days");
        }
        SyncMode::Years { years } => {
            let end = Utc::now();
            let start_dt = end - chrono::Duration::days((years * 365) as i64);
            params_vec.push(("pubStartDate", start_dt.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
            params_vec.push(("pubEndDate", end.format("%Y-%m-%dT%H:%M:%S.000").to_string()));
            eprintln!("[*] Windowed update: CVEs published in last {years} year(s)");
        }
    }

    let client = reqwest::Client::builder()
        .user_agent(DEFAULT_USER_AGENT)
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    let mut total_fetched: u64 = 0;
    let mut total_inserted: u64 = 0;
    let mut latest_last_modified: Option<String> = None;
    let mut batch_cves: Vec<(String, String, Option<String>, Option<f64>, Option<String>, Option<String>, Option<String>, String)> = Vec::new();
    let mut batch_products: Vec<(String, String, String, String, String)> = Vec::new();

    loop {
        let mut params_map = std::collections::HashMap::new();
        for (k, v) in &params_vec {
            params_map.insert(*k, v.clone());
        }
        params_map.insert("startIndex", start_index.to_string());

        let resp = client
            .get(NVD_API_URL)
            .query(&params_map)
            .send()
            .await
            .context("NVD API request failed")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("NVD API returned HTTP {status}: {body}");
        }

        let data: NvdResponse = resp.json().await.context("failed to parse NVD response")?;
        let count = data.vulnerabilities.len() as u64;

        if count == 0 {
            break;
        }

        start_index += count;
        total_fetched += count;

        for vuln in &data.vulnerabilities {
            let cve_id = match &vuln.cve.id {
                Some(id) => id.clone(),
                None => continue,
            };

            let description = get_description(&vuln.cve.descriptions);
            let (cvss_score, cvss_vector) = extract_cvss(&vuln.cve.metrics);
            let severity = extract_severity(&vuln.cve.metrics, cvss_score);
            let published = vuln.cve.published.clone();
            let last_modified = vuln.cve.lastModified.clone();
            let references = get_references(&vuln.cve.references);
            let products = extract_products(&cve_id, &vuln.cve.configurations);

            batch_cves.push((
                cve_id.clone(),
                description,
                severity,
                cvss_score,
                cvss_vector,
                published,
                last_modified.clone(),
                references,
            ));

            for (vendor, product, vstart, vend, cid) in products {
                batch_products.push((cid, vendor, product, vstart, vend));
            }

            if let Some(ref lm) = last_modified {
                if latest_last_modified.as_deref().map_or(true, |cur| lm.as_str() > cur) {
                    latest_last_modified = Some(lm.clone());
                }
            }
        }

        // Batch insert every 1000
        if batch_cves.len() >= 1000 {
            total_inserted += batch_insert(&conn, &batch_cves, &batch_products)?;
            batch_cves.clear();
            batch_products.clear();
        }

        eprintln!("  Progress: {total_fetched} CVEs fetched ({} totalResults)", data.totalResults);

        if start_index >= data.totalResults {
            break;
        }

        // Rate limiting: sleep 0.6s without key, 0.25s with
        if config.api_key.is_some() {
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        } else {
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        }
    }

    // Flush remaining
    if !batch_cves.is_empty() {
        total_inserted += batch_insert(&conn, &batch_cves, &batch_products)?;
    }

    // Update metadata
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_updated', ?1)",
        params![now],
    )?;
    if let Some(ref lm) = latest_last_modified {
        conn.execute(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES ('last_modified', ?1)",
            params![lm],
        )?;
    }

    // Store total count
    let total: u64 = conn
        .query_row("SELECT COUNT(*) FROM cve_entries", [], |row| row.get(0))
        .unwrap_or(0);
    conn.execute(
        "INSERT OR REPLACE INTO metadata (key, value) VALUES ('total_entries', ?1)",
        params![total.to_string()],
    )?;

    let duration_ms = start.elapsed().as_millis() as u64;
    eprintln!(
        "[+] CVE sync complete: {total_fetched} fetched, {total_inserted} inserted/updated ({total} total in DB, {duration_ms}ms)"
    );

    Ok((total_fetched, total_inserted))
}

fn batch_insert(
    conn: &Connection,
    cves: &[(String, String, Option<String>, Option<f64>, Option<String>, Option<String>, Option<String>, String)],
    products: &[(String, String, String, String, String)],
) -> Result<u64> {
    let mut count = 0u64;

    // Insert CVEs
    for cve in cves {
        let result = conn.execute(
            "INSERT OR REPLACE INTO cve_entries (cve_id, description, severity, cvss_score, cvss_vector, published_date, last_modified, \"references\")
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                cve.0, cve.1, cve.2, cve.3, cve.4, cve.5, cve.6, cve.7
            ],
        );
        if let Ok(rows) = result {
            count += rows as u64;
        }
    }

    // Delete old products for these CVEs
    let cve_ids: Vec<&str> = cves.iter().map(|c| c.0.as_str()).collect();
    if !cve_ids.is_empty() {
        let placeholders: Vec<String> = cve_ids.iter().enumerate().map(|(i, _)| format!("?{}", i + 1)).collect();
        let sql = format!(
            "DELETE FROM cve_products WHERE cve_id IN ({})",
            placeholders.join(",")
        );
        let _ = conn.execute(&sql, rusqlite::params_from_iter(cve_ids.iter()));
    }

    // Insert products
    for prod in products {
        let _ = conn.execute(
            "INSERT OR IGNORE INTO cve_products (cve_id, vendor, product, version_start, version_end)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![prod.0, prod.1, prod.2, prod.3, prod.4],
        );
    }

    Ok(count)
}
