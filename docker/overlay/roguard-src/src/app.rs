use crate::roguard::RoGuard;
use crate::sigscan::{SignatureScanner, DEFAULT_ROOTS};
use serde::Serialize;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

/// 内置固定策略
const WATCH_SEC: u64 = 5;     //控制检验readonly的时间间隔
const GRACE: u32 = 1;       //控制

/// 隐藏内部子命令：父进程用来“自启守护”和“后台扫描上传”
#[derive(clap::Parser, Debug)]
#[command(name = "roguar2d", version, about = "Read-only guard & in-memory signature scanner")]
struct Cli {
    /// 仅供父进程自调用：守护进程模式（每5秒复检，违规 exit(1)）
    #[arg(long, hide = true)]
    daemon: bool,
    /// 仅供父进程自调用：扫描并上传一次（内存生成 .jsonl.gz）
    #[arg(long, hide = true)]
    scan_once: bool,
}

pub fn run() -> i32 {
    let cli = <Cli as clap::Parser>::parse();

    if cli.daemon {    // 这两个 if 是给子进程（通过 CLI 参数）走的分支；
        return run_watch();  //  父进程默认路径会 spawn 两个“子进程”分别带 --daemon / --scan-once
    }
    if cli.scan_once {
        return run_scan_once();
    }

    // === 默认路径：无参数 ==
    // 1) 启动前强制校验（失败直接退出，阻断 API Server）
    let g = RoGuard::new();
    let (ok, report) = g.verify_once();
    println!("{}", serde_json::to_string(&report).unwrap());
    if !ok {
        eprintln!("[RO-GUARD] startup check failed");
        return 1;
    }

    // 2) 后台守护（每5秒复检）
    let self_path = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[RO-GUARD] current_exe error: {e}");
            return 1;
        }
    };
    let _ = Command::new(&self_path).arg("--daemon").spawn();

    // 3) 后台签名扫描&上传（一次）
    let _ = Command::new(&self_path).arg("--scan-once").spawn();

    // 父进程即时返回 0，供入口“一行”同步调用
    0
}

fn run_watch() -> i32 {
    let g = RoGuard::new();
    g.watch(Duration::from_secs(WATCH_SEC), GRACE) // ! never returns
}

fn run_scan_once() -> i32 {
    let roots: Vec<PathBuf> = DEFAULT_ROOTS.iter().map(|s| PathBuf::from(s)).collect();
    let scanner = SignatureScanner::new(roots);

    let (gz, summary) = match scanner.run_to_memory() {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SIG-SCAN] error: {e:#}");
            return 2;
        }
    };

    let sent = match scanner.send_to_host(&gz, &summary.root_sha256) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[SIG-SCAN] send error: {e:#}");
            return 4;
        }
    };

    #[derive(Serialize)]
    struct Out<'a> {
        summary: &'a crate::sigscan::Summary,
        sent: &'a crate::sigscan::SendResult,
    }
    println!(
        "{}",
        serde_json::to_string(&Out {
            summary: &summary,
            sent: &sent
        })
        .unwrap()
    );
    if sent.status / 100 == 2 { 0 } else { 5 }
}
