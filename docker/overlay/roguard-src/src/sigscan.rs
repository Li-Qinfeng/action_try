//! # Signature Scanner
//!
//! This module provides a simple way to compute and report a **root-level hash** of all files
//! under certain directories (by default, Python installation paths inside a container).
//!
//! The core idea is:
//! - Traverse configured root directories;
//! - For each file, compute SHA256 + metadata;
//! - Aggregate everything into one deterministic root hash (`root_sha256`);
//! - Send the summary to a host endpoint.
//!
//! ## Example: Use in `main.rs`
//!
//! ```no_run
//! use sigscan::SignatureScanner;
//! use std::process;
//!
//! fn main() {
//!     let scanner = SignatureScanner::new()
//!         .with_upload_url("http://host.docker.internal:17777/upload");
//!
//!     // 1) Compute the root summary
//!     let summary = match scanner.compute_root_summary() {
//!         Ok(s) => s,
//!         Err(e) => {
//!             eprintln!("[error] compute_root_summary: {e:#}");
//!             process::exit(1);
//!         }
//!     };
//!
//!     // 2) Send to host
//!     let sent = match scanner.send_to_host(&summary) {
//!         Ok(r) => r,
//!         Err(e) => {
//!             eprintln!("[error] send_to_host: {e:#}");
//!             process::exit(2);
//!         }
//!     };
//!
//!     println!("{}", serde_json::to_string_pretty(&sent).unwrap());
//! }
//! ```
//!
//! Expected behavior:
//! - On success, prints a JSON containing the HTTP status and snippet;
//! - On failure, exits with a nonzero code.

use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use rayon::prelude::*;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

/// Default directory roots to scan inside the container.
///
/// These paths target common Python installation & site-packages locations.
pub const DEFAULT_ROOTS: &[&str] = &[
    "/usr/local/lib/python3.12",
    "/usr/lib/python3.12",
    "/usr/local/lib/python3.12/dist-packages",
    "/usr/local/lib/python3.12/site-packages",
];

/// Build a default set of directory names to skip while walking the tree.
///
/// Returns a `HashSet<String>` containing entries like `__pycache__`, `.git`, `.svn`.
fn default_skip_dirnames() -> HashSet<String> {
    ["__pycache__", ".git", ".svn"]
        .into_iter()
        .map(|s| s.to_string())
        .collect()
}

/// Minimal summary produced by the scanner. This is the only payload sent to the host.
///
/// Fields:
/// - `typ`: always `"summary"`
/// - `created_at`: RFC3339 (with millis, UTC)
/// - `files`: number of files included
/// - `bytes`: total size of all files (bytes)
/// - `root_sha256`: aggregate hash over `(path, sha256, size, mtime_ns)`
/// - `roots`: the root directories scanned
/// - `platform`: `os-arch` string (e.g., `linux-x86_64`)
#[derive(Debug, Serialize, Clone)]
pub struct Summary {
    #[serde(rename = "type")]
    typ: &'static str,
    pub created_at: String,
    pub files: usize,
    pub bytes: u64,
    pub root_sha256: String,
    pub roots: Vec<String>,
    pub platform: String,
}

/// Result of sending the summary to the host receiver.
///
/// Fields:
/// - `url`: upload URL used
/// - `status`: HTTP status code
/// - `response_snippet`: first 512 chars of the response body (if any)
#[derive(Debug, Serialize, Clone)]
pub struct SendResult {
    pub url: String,
    pub status: u16,
    pub response_snippet: String,
}

/// Content signature scanner. Walks configured roots, hashes files, and computes a single
/// aggregate hash (`root_sha256`) that changes whenever any file's path/content/size/mtime changes.
///
/// Typical usage:
/// ```no_run
/// let scanner = sigscan::SignatureScanner::new();
/// let summary = scanner.compute_root_summary().unwrap();
/// let sent = scanner.send_to_host(&summary).unwrap();
/// println!("{}", serde_json::to_string(&sent).unwrap());
/// ```
pub struct SignatureScanner {
    roots: Vec<PathBuf>,
    skip_dirnames: HashSet<String>,
    workers: Option<usize>,
    pub host_upload_url: String, // Upload destination (can be modified directly)
}

impl SignatureScanner {
    /// Construct a scanner using the built-in `DEFAULT_ROOTS` and reasonable defaults.
    ///
    /// - Skips directories returned by `default_skip_dirnames()`;
    /// - By default, worker threads = logical CPU count (configurable via `workers`).
    pub fn new() -> Self {
        let roots = DEFAULT_ROOTS
            .iter()
            .map(|s| PathBuf::from(s))
            .collect::<Vec<_>>();
        Self {
            roots,
            skip_dirnames: default_skip_dirnames(),
            workers: None,
            host_upload_url: "http://host.docker.internal:17777/upload".to_string(),
        }
    }

    /// Chainable setter to override the upload URL.
    ///
    /// # Example
    /// ```no_run
    /// let scanner = sigscan::SignatureScanner::new()
    ///     .with_upload_url("http://my-host:17777/upload");
    /// ```
    pub fn with_upload_url(mut self, url: impl Into<String>) -> Self {
        self.host_upload_url = url.into();
        self
    }

    /// Chainable setter to control the number of worker threads (Rayon pool).
    ///
    /// If `None`, the scanner will use the logical CPU count.
    pub fn workers(mut self, n: Option<usize>) -> Self {
        self.workers = n;
        self
    }

    /// Walk all roots, hash all files, and compute the aggregate `root_sha256`.
    ///
    /// The aggregate hash is computed over a canonical byte sequence for each file:
    /// `path_bytes 0x00 sha256_hex 0x00 size_ascii 0x00 mtime_ns_ascii '\n'`,
    /// concatenated in sorted path order (order preserved via indexing).
    ///
    /// Returns a `Summary` with `files`, `bytes`, `root_sha256`, and metadata.
    pub fn compute_root_summary(&self) -> Result<Summary> {
        let files = self.walk_files();
        let metas = self.hash_all_in_order(&files)?; // (sha256_hex, size, mtime_ns, mode_str)

        if files.len() != metas.len() {
            bail!("paths/meta length mismatch");
        }

        let mut total_files = 0usize;
        let mut total_bytes = 0u64;
        let mut root_hasher = Sha256::new();

        // Aggregate hash over (path_bytes, sha256, size, mtime_ns) for all files
        for (p, (sha256, size, mtime_ns, _mode_str)) in files.iter().zip(metas.iter()) {
            if sha256.is_empty() && *size == 0 && *mtime_ns == 0 {
                continue;
            }
            total_files += 1;
            total_bytes += *size;

            let path_bytes = p.as_os_str().as_bytes();
            root_hasher.update(path_bytes);
            root_hasher.update(&[0]);
            root_hasher.update(sha256.as_bytes());
            root_hasher.update(&[0]);
            root_hasher.update(size.to_string().as_bytes());
            root_hasher.update(&[0]);
            root_hasher.update(mtime_ns.to_string().as_bytes());
            root_hasher.update(b"\n");
        }

        let summary = Summary {
            typ: "summary",
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            files: total_files,
            bytes: total_bytes,
            root_sha256: format!("{:x}", root_hasher.finalize()),
            roots: self
                .roots
                .iter()
                .map(|p| p.to_string_lossy().to_string())
                .collect(),
            platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        };

        Ok(summary)
    }

    /// Send the `Summary` JSON to the configured `host_upload_url`.
    ///
    /// - Sets `Content-Type: application/json`
    /// - Adds header `X-Root-SHA256: <summary.root_sha256>`
    ///
    /// Returns a `SendResult` with status code and a short response snippet.
    pub fn send_to_host(&self, summary: &Summary) -> Result<SendResult> {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        h.insert(
            HeaderName::from_static("x-root-sha256"),
            HeaderValue::from_str(&summary.root_sha256)
                .unwrap_or_else(|_| HeaderValue::from_static("invalid")),
        );

        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()?;

        let body = serde_json::to_vec(summary)?;
        let resp = client.post(&self.host_upload_url).headers(h).body(body).send()?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        let snippet = text.chars().take(512).collect();

        Ok(SendResult {
            url: self.host_upload_url.clone(),
            status,
            response_snippet: snippet,
        })
    }

    // ============== Internal: traversal and parallel hashing ==============

    /// Recursively walk all configured roots and collect regular files.
    ///
    /// - Follows neither symlinks nor cross-filesystem transitions;
    /// - Skips directories in `skip_dirnames`;
    /// - Returns a sorted `Vec<PathBuf>` for deterministic ordering.
    fn walk_files(&self) -> Vec<PathBuf> {
        let mut acc = Vec::<PathBuf>::new();
        for root in &self.roots {
            if !root.exists() {
                continue;
            }
            let it = WalkDir::new(root)
                .follow_links(false)
                .same_file_system(false)
                .into_iter()
                .filter_entry(|e| self.filter_entry(e));
            for ent in it.filter_map(|e| e.ok()) {
                if ent.file_type().is_file() {
                    acc.push(ent.path().to_path_buf());
                }
            }
        }
        acc.sort();
        acc
    }

    /// Filter callback for `walkdir`: returns `false` to prune a directory.
    ///
    /// - Always keep depth 0 (the root itself);
    /// - If the entry is a directory and its name is in `skip_dirnames`, prune it;
    /// - Otherwise, keep it.
    fn filter_entry(&self, e: &DirEntry) -> bool {
        if e.depth() == 0 {
            return true;
        }
        if e.file_type().is_dir() {
            if let Some(name) = e.file_name().to_str() {
                return !self.skip_dirnames.contains(name);
            }
        }
        true
    }

    /// Hash all files in parallel and return results **in the same order** as input `files`.
    ///
    /// Internally uses Rayon with either the configured `workers` or logical CPU count to compute
    /// `(sha256_hex, size, mtime_ns, mode_str)` for each file, then reorders results by original index.
    fn hash_all_in_order(&self, files: &[PathBuf]) -> Result<Vec<(String, u64, i128, String)>> {
        let worker_count = self.workers.unwrap_or_else(Self::num_cpus);
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(worker_count.max(1))
            .build()
            .context("build rayon thread pool")?;
        let mut out: Vec<(usize, (String, u64, i128, String))> = pool.install(|| {
            files
                .par_iter()
                .enumerate()
                .map(|(i, p)| (i, Self::hash_one(p)))
                .collect()
        });
        out.sort_by_key(|(i, _)| *i);
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }

    /// Return the logical CPU count; fallback to `4` if detection fails.
    fn num_cpus() -> usize {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
    }

    /// Hash a single file's contents with SHA-256 and return:
    /// `(sha256_hex, size_bytes, mtime_ns, mode_octal_string)`.
    ///
    /// Returns zeros/empty strings for non-regular files or on metadata/open/read errors.
    fn hash_one(p: &Path) -> (String, u64, i128, String) {
        let meta = match std::fs::symlink_metadata(p) {
            Ok(m) => m,
            Err(_) => return ("".into(), 0, 0, "0".into()),
        };
        let mode = meta.mode();
        let is_reg = (mode & libc::S_IFMT) == libc::S_IFREG;
        if !is_reg {
            return ("".into(), 0, 0, "0".into());
        }
        let size = meta.size();
        let mtime_ns = (meta.mtime() as i128) * 1_000_000_000i128 + (meta.mtime_nsec() as i128);
        let mode_str = format!("{:#o}", mode & 0o7777);

        let mut hasher = sha2::Sha256::new();
        if let Ok(mut f) = File::open(p) {
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                match Read::read(&mut f, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => hasher.update(&buf[..n]),
                    Err(_) => break,
                }
            }
        }
        let sha_hex = format!("{:x}", hasher.finalize());
        (sha_hex, size, mtime_ns, mode_str)
    }
}
