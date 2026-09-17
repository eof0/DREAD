//! Concurrent HTTP GET fast-core for DREAD's Probe crawler (Rust variant).
//!
//! Reads one JSON request object from stdin and writes a JSON array of results to
//! stdout — the exact same protocol as the Go fetcher (`fetch.go`) it sits alongside,
//! so Python's `bulk_get()` can drive whichever compiled engine is available without
//! caring which one it got. Exists to collapse many sequential, rate-limited existence
//! probes (content discovery over common routes) into one concurrent batch.

use std::collections::HashMap;
use std::io::Read;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct FetchRequest {
    urls: Vec<String>,
    #[serde(default = "default_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_concurrency")]
    concurrency: usize,
    #[serde(default)]
    headers: HashMap<String, String>,
    #[serde(default)]
    proxy: String,
    #[serde(default = "default_max_body")]
    max_body: usize,
    #[serde(default)]
    allow_redirects: bool,
    // Skips TLS verification -- mirrors RequestHandler(verify_ssl=False), for scanning
    // targets with self-signed/broken certs. Defaults to verifying.
    #[serde(default)]
    insecure: bool,
}

fn default_timeout_ms() -> u64 {
    8000
}

fn default_concurrency() -> usize {
    50
}

fn default_max_body() -> usize {
    200_000
}

#[derive(Serialize)]
struct FetchResult {
    url: String,
    status: u16,
    headers: HashMap<String, String>,
    body: String,
    error: String,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && args[1] == "--version" {
        println!("dread-http-fetch-rs 1.0");
        return;
    }

    let mut input = String::new();
    if std::io::stdin().read_to_string(&mut input).is_err() {
        std::process::exit(1);
    }
    let req: FetchRequest = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(_) => std::process::exit(1),
    };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to start async runtime");
    let results = rt.block_on(run(req));

    let stdout = std::io::stdout();
    if serde_json::to_writer(stdout.lock(), &results).is_err() {
        std::process::exit(1);
    }
}

async fn run(req: FetchRequest) -> Vec<FetchResult> {
    let timeout_ms = if req.timeout_ms == 0 { default_timeout_ms() } else { req.timeout_ms };
    let concurrency = if req.concurrency == 0 { default_concurrency() } else { req.concurrency };
    let max_body = if req.max_body == 0 { default_max_body() } else { req.max_body };

    let mut header_map = HeaderMap::new();
    for (k, v) in &req.headers {
        // A malformed header from the caller must not sink the whole batch -- skip it.
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(k.as_bytes()),
            HeaderValue::from_str(v),
        ) {
            header_map.insert(name, value);
        }
    }

    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .danger_accept_invalid_certs(req.insecure)
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .default_headers(header_map)
        .redirect(if req.allow_redirects {
            reqwest::redirect::Policy::limited(10)
        } else {
            reqwest::redirect::Policy::none()
        });

    if !req.proxy.is_empty() {
        if let Ok(proxy) = reqwest::Proxy::all(&req.proxy) {
            builder = builder.proxy(proxy);
        }
    }

    let client = match builder.build() {
        Ok(c) => c,
        Err(_) => reqwest::Client::new(),
    };

    // `buffered` (not `buffer_unordered`): still runs up to `concurrency` requests at
    // once, but yields results in the original input order -- matching the Go fetcher's
    // indexed-array output and Python's ThreadPoolExecutor.map, so callers see identical
    // ordering no matter which engine actually served the batch.
    stream::iter(req.urls.into_iter())
        .map(|url| {
            let client = client.clone();
            async move { fetch_one(&client, url, max_body).await }
        })
        .buffered(concurrency.max(1))
        .collect::<Vec<_>>()
        .await
}

async fn fetch_one(client: &reqwest::Client, url: String, max_body: usize) -> FetchResult {
    let response = match client.get(&url).send().await {
        Ok(resp) => resp,
        Err(err) => {
            return FetchResult {
                url,
                status: 0,
                headers: HashMap::new(),
                body: String::new(),
                error: err.to_string(),
            }
        }
    };

    let status = response.status().as_u16();
    // Go's fetcher keeps the FIRST value per header name (http.Header.Get semantics) --
    // match that instead of concatenating repeated headers (e.g. Set-Cookie).
    let mut headers = HashMap::new();
    for name in response.headers().keys() {
        if let Some(value) = response.headers().get(name) {
            headers.insert(name.to_string(), value.to_str().unwrap_or_default().to_string());
        }
    }

    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(err) => {
            return FetchResult { url, status, headers, body: String::new(), error: err.to_string() }
        }
    };
    let capped = &bytes[..bytes.len().min(max_body)];
    let body = String::from_utf8_lossy(capped).into_owned();

    FetchResult { url, status, headers, body, error: String::new() }
}
