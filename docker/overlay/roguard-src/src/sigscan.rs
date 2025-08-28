use anyhow::{bail, Context, Result};
use chrono::{SecondsFormat, Utc};
use flate2::{write::GzEncoder, Compression};
use rayon::prelude::*;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, CONTENT_TYPE};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::{DirEntry, WalkDir};

const HOST_UPLOAD_URL: &str = "http://host.docker.internal:17777/upload";

pub const DEFAULT_ROOTS: &[&str] = &[
    "/usr/local/lib/python3.12",
    "/usr/lib/python3.12",
    "/usr/local/lib/python3.12/dist-packages",
    "/usr/local/lib/python3.12/site-packages",
];

fn default_skip_dirnames() -> HashSet<String> {
    ["__pycache__", ".git", ".svn"].into_iter().map(|s| s.to_string()).collect()
}

#[derive(Debug, Serialize)]
struct Header {
    #[serde(rename = "type")]
    typ: &'static str,
    version: u32,
    algo: &'static str,
    created_at: String,
    roots: Vec<String>,
    python: &'static str,
    platform: String,
}

#[derive(Debug, Serialize)]
struct FileRec {
    #[serde(rename = "type")]
    typ: &'static str,
    path: String,
    sha256: String,
    size: u64,
    mtime_ns: i128,
    mode: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct Summary {
    #[serde(rename = "type")]
    typ: &'static str,
    pub files: usize,
    pub bytes: u64,
    pub root_sha256: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct SendResult {
    pub url: String,
    pub status: u16,
    pub response_snippet: String,
}

pub struct SignatureScanner {
    roots: Vec<PathBuf>,
    skip_dirnames: HashSet<String>,
    workers: Option<usize>,
}

impl SignatureScanner {
    pub fn new<P: Into<PathBuf>>(roots: Vec<P>) -> Self {
        Self {
            roots: roots.into_iter().map(Into::into).collect(),
            skip_dirnames: default_skip_dirnames(),
            workers: None,
        }
    }
    pub fn workers(mut self, n: Option<usize>) -> Self { self.workers = n; self }

    pub fn run_to_memory(&self) -> Result<(Vec<u8>, Summary)> {
        let files = self.walk_files();    // 遍历要扫描的根目录，收集所有常规文件路径（返回 Vec<PathBuf>）
        let paths: Vec<String> = files.iter().map(|p| p.to_string_lossy().into_owned()).collect();    // 把路径统一转成字符串列表（保证稳定输出顺序）
        let metas = self.hash_all_in_order(&files)?;    // 按顺序对每个文件计算 SHA256、大小、mtime、权限等元信息
        let mut gz = GzEncoder::new(Vec::new(), Compression::default());    // 创建一个 gzip 压缩写入器，底层输出目标是内存里的 Vec<u8>
        let summary = self.write_jsonl(&mut gz, &paths, &metas)?;    // 把 header、文件记录、summary 按 JSONL 格式写入 gzip 压缩流，并返回汇总信息
        let gz_bytes = gz.finish()?;     // 结束压缩，取出完整的 gzip 压缩字节数组
        Ok((gz_bytes, summary))     // 返回：压缩包的字节 Vec<u8> + 扫描的统计摘要 Summary
    }

    pub fn send_to_host(&self, gz_bytes: &[u8], root_sha256: &str) -> Result<SendResult> {
        let mut h = HeaderMap::new();
        h.insert(CONTENT_TYPE, HeaderValue::from_static("application/gzip"));
        h.insert(HeaderName::from_static("x-root-sha256"),
                 HeaderValue::from_str(root_sha256).unwrap_or_else(|_| HeaderValue::from_static("invalid")));
        let client = Client::builder().timeout(std::time::Duration::from_secs(15)).build()?;
        let resp = client.post(HOST_UPLOAD_URL).headers(h).body(gz_bytes.to_vec()).send()?;
        let status = resp.status().as_u16();
        let text = resp.text().unwrap_or_default();
        let snippet = text.chars().take(512).collect();
        Ok(SendResult { url: HOST_UPLOAD_URL.to_string(), status, response_snippet: snippet })
    }

    fn walk_files(&self) -> Vec<PathBuf> {
        let mut acc = Vec::<PathBuf>::new();
        for root in &self.roots {
            if !root.exists() { continue; }
            let it = WalkDir::new(root).follow_links(false).same_file_system(false)
                .into_iter().filter_entry(|e| self.filter_entry(e));
            for ent in it.filter_map(|e| e.ok()) {
                if ent.file_type().is_file() { acc.push(ent.path().to_path_buf()); }
            }
        }
        acc.sort();
        acc
    }
    fn filter_entry(&self, e: &DirEntry) -> bool {
        if e.depth() == 0 { return true; }
        if e.file_type().is_dir() {
            if let Some(name) = e.file_name().to_str() { return !self.skip_dirnames.contains(name); }
        }
        true
    }
    fn hash_all_in_order(&self, files: &[PathBuf]) -> Result<Vec<(String, u64, i128, String)>> {    
        let worker_count = self.workers.unwrap_or_else(num_cpus);
        let pool = rayon::ThreadPoolBuilder::new().num_threads(worker_count.max(1)).build()
            .context("build rayon thread pool")?;
        let mut out: Vec<(usize, (String, u64, i128, String))> = pool.install(|| {
            files.par_iter().enumerate().map(|(i, p)| (i, Self::hash_one(p))).collect()
        });
        out.sort_by_key(|(i, _)| *i);
        Ok(out.into_iter().map(|(_, v)| v).collect())
    }
    fn hash_one(p: &Path) -> (String, u64, i128, String) {   //把一个文件的meta内容转换成哈希，输出：一个四元组 (sha256_hex, 文件大小, 修改时间纳秒, 权限字符串)
        let meta = match std::fs::symlink_metadata(p) { Ok(m) => m, Err(_) => return ("".into(), 0, 0, "0".into()) };
        let mode = meta.mode();
        let is_reg = (mode & libc::S_IFMT) == libc::S_IFREG;
        if !is_reg { return ("".into(), 0, 0, "0".into()); }
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
    fn write_jsonl<W: Write>(&self, writer: &mut W, paths: &[String], metas: &[(String, u64, i128, String)]) -> Result<Summary> {    //把计算好的哈希及其对应内容都写到gz里面
        if paths.len() != metas.len() { bail!("paths/meta length mismatch"); }
        let header = Header {
            typ: "header", version: 1, algo: "sha256",
            created_at: Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            roots: self.roots.iter().map(|p| p.to_string_lossy().to_string()).collect(),
            python: "N/A", platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        };
        serde_json::to_writer(&mut *writer, &header)?; writer.write_all(b"\n")?;
        let mut total_files = 0usize; let mut total_bytes = 0u64; let mut root_hasher = Sha256::new();
        for (path, (sha256, size, mtime_ns, mode_str)) in paths.iter().zip(metas.iter()) {
            if sha256.is_empty() && *size == 0 && *mtime_ns == 0 { continue; }
            let rec = FileRec { typ: "file", path: path.clone(), sha256: sha256.clone(), size: *size, mtime_ns: *mtime_ns, mode: mode_str.clone() };
            serde_json::to_writer(&mut *writer, &rec)?; writer.write_all(b"\n")?;
            total_files += 1; total_bytes += *size;
            root_hasher.update(path.as_bytes()); root_hasher.update(&[0]);
            root_hasher.update(sha256.as_bytes()); root_hasher.update(&[0]);
            root_hasher.update(size.to_string().as_bytes()); root_hasher.update(&[0]);
            root_hasher.update(mtime_ns.to_string().as_bytes()); root_hasher.update(b"\n");
        }
        let summary = Summary { typ: "summary", files: total_files, bytes: total_bytes, root_sha256: format!("{:x}", root_hasher.finalize()) };
        serde_json::to_writer(&mut *writer, &summary)?; writer.write_all(b"\n")?;
        Ok(summary)
    }
}
fn num_cpus() -> usize { std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4) }
