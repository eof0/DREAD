use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::time::Instant;

mod scan;
mod schema;
mod cve_sync;
mod cve_lookup;

use scan::{resolve_ports_from_str, resolve_target, tcp_connect_scan, ScanConfig, resolve_ports};
use schema::{ScanResult, Target, CveSyncResult, CveLookupResult};
use cve_sync::{sync_cves, CveSyncConfig, SyncMode};
use cve_lookup::{lookup_cves, LookupConfig};

#[derive(Parser, Debug)]
#[command(name = "probe-engine", version, about = "Probe scanning engine (Rust)")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run a TCP port scan against a target
    Scan {
        /// Target hostname/IP
        #[arg(long)]
        input: String,

        /// Ports: "1-1024", "80,443,8080", "top100", "top1000"
        #[arg(long, default_value = "top100")]
        ports: String,

        /// Per-connection timeout in ms
        #[arg(long, default_value_t = 800)]
        timeout_ms: u64,

        /// Max concurrent connections
        #[arg(long, default_value_t = 512)]
        concurrency: usize,

        /// Grab service banners on open ports
        #[arg(long, default_value_t = false)]
        banners: bool,

        /// Emit JSON to stdout
        #[arg(long, default_value_t = true)]
        json: bool,
    },
    /// Sync CVEs from NVD into the local SQLite database
    CveSync {
        /// Path to CVE SQLite database
        #[arg(long)]
        db_path: String,

        /// Full NVD corpus sync (ignore date windows)
        #[arg(long, default_value_t = false)]
        full: bool,

        /// Incremental sync (only modified since last cursor)
        #[arg(long, default_value_t = false)]
        incremental: bool,

        /// Window: CVEs published in last N days
        #[arg(long)]
        days: Option<u64>,

        /// Window: CVEs published in last N years
        #[arg(long)]
        years: Option<u64>,

        /// NVD API key (for higher rate limits)
        #[arg(long)]
        api_key: Option<String>,
    },
    /// Look up CVEs for a product/version in the local database
    CveLookup {
        /// Path to CVE SQLite database
        #[arg(long)]
        db_path: String,

        /// Product name (e.g. "nginx", "wordpress")
        #[arg(long)]
        product: String,

        /// Version string (e.g. "1.18.0")
        #[arg(long)]
        version: Option<String>,

        /// Vendor filter (overrides automatic detection)
        #[arg(long)]
        vendor: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.cmd {
        Commands::Scan {
            input,
            ports,
            timeout_ms,
            concurrency,
            banners,
            json,
        } => {
            let started = Instant::now();

            let port_spec = resolve_ports_from_str(&ports).context("invalid --ports")?;
            let port_list = resolve_ports(&port_spec);
            let resolved = resolve_target(&input).await.context("failed to resolve target")?;

            let config = ScanConfig {
                ports: port_spec,
                timeout_ms,
                concurrency,
                grab_banners: banners,
            };

            let mut findings = Vec::new();
            for ip in &resolved {
                let mut f = tcp_connect_scan(ip, &port_list, &config).await?;
                findings.append(&mut f);
            }

            let result = ScanResult::new(
                Target { input, resolved },
                started.elapsed().as_millis() as u64,
                findings,
            );

            if json {
                println!("{}", serde_json::to_string_pretty(&result)?);
            }

            Ok(())
        }

        Commands::CveSync {
            db_path,
            full,
            incremental,
            days,
            years,
            api_key,
        } => {
            let started = Instant::now();

            let mode = if full {
                SyncMode::Full
            } else if incremental {
                SyncMode::Incremental
            } else if let Some(y) = years {
                SyncMode::Years { years: y }
            } else {
                SyncMode::Window {
                    days: days.unwrap_or(30),
                }
            };

            let config = CveSyncConfig {
                db_path: db_path.clone(),
                mode,
                api_key,
                batch_size: 2000,
            };

            let (fetched, inserted) = sync_cves(config).await?;

            let result = CveSyncResult {
                total_fetched: fetched,
                total_inserted: inserted,
                duration_ms: started.elapsed().as_millis() as u64,
                db_path,
            };

            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }

        Commands::CveLookup {
            db_path,
            product,
            version,
            vendor,
        } => {
            let config = LookupConfig {
                db_path,
                product,
                version,
                vendor,
            };

            let entries = lookup_cves(&config)?;
            let total = entries.len();

            let result = CveLookupResult {
                query: config.product,
                version_filter: config.version,
                total,
                results: entries,
            };

            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}
