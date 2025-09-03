mod roguard;
mod sigscan;

use std::time::Duration;

fn main() {
    // ① 启动前只读校验（失败直接退出）
    let (ok, report) = roguard::RoGuard::new().verify_once();
    println!("{}", serde_json::to_string(&report).unwrap());
    if !ok {
        std::process::exit(1);
    }

    // ② 后台只读守护（固定 5s / 容忍 1 次）
    std::thread::spawn(|| {
        roguard::RoGuard::new().watch(Duration::from_secs(5), 1)
    });

    // ③ 计算整体哈希并上报：new → compute → send
    let scanner = sigscan::SignatureScanner::new();
    // 如需自定义上报地址：let scanner = sigscan::SignatureScanner::new().with_upload_url("http://host:17777/upload");

    let summary = match scanner.compute_root_summary() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[hash_compute] {e:#}");
            std::process::exit(4);
        }
    };
    let sent = match scanner.send_to_host(&summary) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[hash_send] {e:#}");
            std::process::exit(4);
        }
    };
    println!("{}", serde_json::to_string(&sent).unwrap());
    if sent.status / 100 != 2 {
        std::process::exit(5);
    }
}
