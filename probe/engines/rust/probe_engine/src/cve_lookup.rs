use anyhow::{Context, Result};
use rusqlite::Connection;
use serde_json;

use crate::schema::CveEntry;

/// Known product aliases mapping detected technology names -> CPE product names.
const PRODUCT_ALIASES: &[(&str, &[&str])] = &[
    ("wordpress", &["wordpress", "wp"]),
    ("apache", &["apache", "apache_http_server", "httpd", "apache_httpd"]),
    ("nginx", &["nginx", "nginx_proxy", "nginx_plus"]),
    ("mysql", &["mysql", "oracle_mysql", "mariadb"]),
    ("mariadb", &["mariadb", "mysql"]),
    ("postgresql", &["postgresql", "postgres"]),
    ("mongodb", &["mongodb", "mongo_db"]),
    ("redis", &["redis", "redis_server"]),
    ("laravel", &["laravel"]),
    ("django", &["django"]),
    ("rails", &["rails", "ruby_on_rails"]),
    ("nodejs", &["nodejs", "node.js", "node_js"]),
    ("php", &["php", "php_fpm", "php_cli"]),
    ("python", &["python"]),
    ("java", &["java", "oracle_java", "openjdk", "jdk", "jre"]),
    ("astro", &["astro"]),
    ("cloudflare", &["cloudflare"]),
    ("tomcat", &["tomcat", "apache_tomcat"]),
    ("iis", &["iis", "microsoft_iis"]),
];

/// Known CPE vendors for technologies (used for vendor filtering).
const PRODUCT_VENDORS: &[(&str, &str)] = &[
    ("wordpress", "wordpress"),
    ("apache", "apache"),
    ("nginx", "nginx"),
    ("mysql", "mysql"),
    ("mariadb", "mariadb"),
    ("postgresql", "postgresql"),
    ("mongodb", "mongodb"),
    ("redis", "redis"),
    ("laravel", "laravel"),
    ("django", "django"),
    ("rails", "rails"),
    ("nodejs", "nodejs"),
    ("php", "php"),
    ("python", "python"),
    ("java", "java"),
    ("astro", "astro"),
    ("cloudflare", "cloudflare"),
];

fn get_cpe_names(product: &str) -> Vec<String> {
    let lower = product.to_lowercase();
    for (name, aliases) in PRODUCT_ALIASES {
        if lower == *name {
            return aliases.iter().map(|s| s.to_string()).collect();
        }
        for alias in *aliases {
            if lower == *alias {
                return aliases.iter().map(|s| s.to_string()).collect();
            }
        }
    }
    vec![lower]
}

fn get_expected_vendor(product: &str) -> Option<&'static str> {
    let lower = product.to_lowercase();
    for (name, vendor) in PRODUCT_VENDORS {
        if lower == *name {
            return Some(vendor);
        }
    }
    None
}

pub struct LookupConfig {
    pub db_path: String,
    pub product: String,
    pub version: Option<String>,
    pub vendor: Option<String>,
}

pub fn lookup_cves(config: &LookupConfig) -> Result<Vec<CveEntry>> {
    let conn = Connection::open(&config.db_path).context("failed to open CVE database")?;

    let cpe_names = get_cpe_names(&config.product);
    if cpe_names.is_empty() {
        return Ok(Vec::new());
    }

    let expected_vendor = config
        .vendor
        .clone()
        .or_else(|| get_expected_vendor(&config.product).map(|s| s.to_string()));

    let placeholders: Vec<String> = cpe_names
        .iter()
        .enumerate()
        .map(|(i, _)| format!("?{}", i + 1))
        .collect();

    let mut sql = format!(
        "SELECT DISTINCT c.cve_id, c.description, c.severity,
                c.cvss_score, c.published_date, c.\"references\"
         FROM cve_entries c
         JOIN cve_products p ON c.cve_id = p.cve_id
         WHERE p.product IN ({})",
        placeholders.join(",")
    );

    let mut param_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
    for name in &cpe_names {
        param_values.push(Box::new(name.clone()));
    }

    if let Some(ref vendor) = expected_vendor {
        sql.push_str(&format!(" AND p.vendor = ?{}", param_values.len() + 1));
        param_values.push(Box::new(vendor.clone()));
    }

    if let Some(ref version) = config.version {
        let v_start = format!("?{}", param_values.len() + 1);
        let v_end = format!("?{}", param_values.len() + 2);
        sql.push_str(&format!(
            " AND (
                (p.version_start IS NULL OR {} >= p.version_start)
                AND (p.version_end IS NULL OR {} <= p.version_end)
            )",
            v_start, v_end
        ));
        param_values.push(Box::new(version.clone()));
        param_values.push(Box::new(version.clone()));
    }

    sql.push_str(" ORDER BY c.cvss_score DESC NULLS LAST");

    let mut stmt = conn.prepare(&sql)?;

    let params_refs: Vec<&dyn rusqlite::types::ToSql> = param_values.iter().map(|p| p.as_ref()).collect();
    let rows = stmt.query_map(params_refs.as_slice(), |row| {
        let refs_str: String = row.get(5).unwrap_or_default();
        let references: Vec<String> = serde_json::from_str(&refs_str).unwrap_or_default();
        Ok(CveEntry {
            cve_id: row.get(0)?,
            description: row.get(1)?,
            severity: row.get(2)?,
            cvss_score: row.get(3)?,
            published_date: row.get(4)?,
            references,
        })
    })?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row?);
    }

    Ok(results)
}
