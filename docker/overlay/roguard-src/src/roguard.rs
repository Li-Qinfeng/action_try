use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::process::Command;

use std::time::Duration;   // 文件顶部已有 imports 的话，补这一行
use std::thread;


const PROBE_PATH: &str = "/.__ro_probe__";
const CAP_SYS_ADMIN_BIT: u64 = 1 << 21;
const CAP_MKNOD_BIT: u64 = 1 << 27;

/// 单条挂载信息
#[derive(Debug, Clone)]
struct MountEntry {
    mp: String,                    // 挂载点
    opts: HashSet<String>,         // mount options（逗号分隔）
    fstype: String,                // 文件系统类型
    src: String,                   // 源（设备/路径）
}

/// 输出报告（字段名与 Python 版本保持一致）
#[derive(Debug, Serialize)]
pub struct Report {
    pub ro_violations: Vec<String>,
    pub unexpected_rw_mounts: Vec<String>,
    pub allowed_but_not_memfs: Vec<String>,
    pub root_write_probe: RootWriteProbe,
    pub cap_violations: Vec<String>,
    pub remount_root_blocked: bool,
    pub remount_msg: String,
    pub allowed_rw_whitelist: Vec<String>,
    pub required_ro: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RootWriteProbe {
    pub ok: bool,
    pub need: &'static str, // 固定 "EROFS"
}

/// 面向对象封装
/// RO 策略配置：限定哪些挂载点必须只读、哪些目录允许写且必须是内存盘等
pub struct RoGuard {
    ro_allowed_rw: HashSet<String>,    // 只读模式下“允许写”的挂载点白名单（如 /tmp、/dev/shm、/root/.cache、/root/.triton）
    ro_required_ro: HashSet<String>,   // 必须为只读(ro)的挂载点集合（如 / 和 /model）
    ro_mem_fs: HashSet<String>,        // 白名单挂载点要求的文件系统类型（仅允许内存盘：tmpfs/ramfs）
    ro_ign_fstypes: HashSet<String>,   // 扫描时忽略的虚拟/系统文件系统类型（proc、sysfs、cgroup 等）
    ro_ign_prefixes: Vec<String>,      // 扫描时忽略的路径前缀（/proc、/sys、/dev 等）
}


impl Default for RoGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RoGuard {
    /// 常量集合初始化（与 Python 版本保持一致）
    pub fn new() -> Self {
        let ro_allowed_rw = HashSet::from_iter([
            "/dev".to_string(),
            "/tmp".to_string(),
            "/root/.triton".to_string(),
            "/root/.cache".to_string(),
        ]);

        let ro_required_ro = HashSet::from_iter([
            "/".to_string(),
            "/model".to_string(),
        ]);

        let ro_mem_fs = HashSet::from_iter([
            "tmpfs".to_string(),
            "ramfs".to_string(),
        ]);

        let ro_ign_fstypes = HashSet::from_iter([
            "proc","sysfs","devpts","mqueue","cgroup","cgroup2","pstore",
            "binfmt_misc","securityfs","debugfs","tracefs","fusectl","configfs",
            // "hugetlbfs",
            "rpc_pipefs","nsfs",
        ].into_iter().map(|s| s.to_string()));

        let ro_ign_prefixes = vec![
            "/proc".to_string(),
            "/sys".to_string(),
        ];

        RoGuard {
            ro_allowed_rw,
            ro_required_ro,
            ro_mem_fs,
            ro_ign_fstypes,
            ro_ign_prefixes,
        }
    }

    /// ===== A) 解析 /proc/self/mountinfo =====
    fn parse_mountinfo(&self) -> io::Result<Vec<MountEntry>> {
        let mut s = String::new();
        fs::File::open("/proc/self/mountinfo")?.read_to_string(&mut s)?;
        let mut out = Vec::new();

        for line in s.lines() {
            // 形如：<left> - <fstype> <src> <superopts>
            let mut parts = line.splitn(2, " - ");
            let left = parts.next().unwrap_or("");
            let right = parts.next().unwrap_or("");
            let l: Vec<&str> = left.split_whitespace().collect();
            let r: Vec<&str> = right.split_whitespace().collect();

            // 第 5 列挂载点，第 6 列 options
            let mp = l.get(4).copied().unwrap_or("").to_string();
            let opts_str = l.get(5).copied().unwrap_or("");
            let opts: HashSet<String> =
                if opts_str.is_empty() { HashSet::new() }
                else { opts_str.split(',').map(|s| s.to_string()).collect() };

            let fstype = r.get(0).copied().unwrap_or("").to_string();
            let src = r.get(1).copied().unwrap_or("").to_string();

            out.push(MountEntry { mp, opts, fstype, src });
        }
        Ok(out)
    }

    /// 是否忽略此挂载（与 Python 逻辑等价）
    fn should_ignore(&self, me: &MountEntry) -> bool {
        if me.mp == "/" {
            return false;
        }
        if self.ro_ign_fstypes.contains(me.fstype.as_str()) {
            return true;
        }
        for p in &self.ro_ign_prefixes {
            if me.mp.starts_with(p) {
                return true;
            }
        }
        false
    }

    /// 根据目标路径查找挂载
    fn get_mount<'a>(&self, mounts: &'a [MountEntry], target: &str) -> Option<&'a MountEntry> {
        mounts.iter().find(|m| m.mp == target)
    }

    /// ===== C) 写探针：期望在只读根上得到 EROFS =====
    fn write_probe(&self, path: &str) -> (bool, String) {
        // Python: open(path, "w") -> create or truncate; write succeeds if root可写
        match fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
        {
            Ok(_) => {
                let _ = fs::remove_file(path);
                (true, "write succeeded".to_string())
            }
            Err(e) => {
                if let Some(code) = e.raw_os_error() {
                    if code == 30 { // EROFS
                        return (false, "EROFS".to_string());
                    }
                }
                (false, format!("error: {}", e))
            }
        }
    }


    /// ===== D1) 能力位读取：CapEff =====
    fn caps_eff(&self) -> u64 {
        let mut s = String::new();
        if let Ok(mut f) = fs::File::open("/proc/self/status") {
            if f.read_to_string(&mut s).is_ok() {
                for line in s.lines() {
                    if line.starts_with("CapEff:") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(hexstr) = parts.get(1) {
                            if let Ok(v) = u64::from_str_radix(hexstr, 16) {
                                return v;
                            }
                        }
                    }
                }
            }
        }
        0
    }

    /// ===== D2) remount 尝试：期望失败 =====
    fn try_remount_root_rw(&self) -> (bool, String) {
        // true = blocked；false = 成功（不安全）
        match Command::new("mount")
            .arg("-o").arg("remount,rw")
            .arg("/")
            .output()
        {
            Ok(out) => {
                let blocked = !out.status.success();
                let mut msg = String::new();
                if !out.stderr.is_empty() {
                    msg = String::from_utf8_lossy(&out.stderr).trim().to_string();
                } else if !out.stdout.is_empty() {
                    msg = String::from_utf8_lossy(&out.stdout).trim().to_string();
                }
                (blocked, msg)
            }
            Err(e) => (true, e.to_string()),
        }
    }

    /// ===== 公共方法：一次性校验 =====
    pub fn verify_once(&self) -> (bool, Report) {
        // 读取挂载信息
        let mounts = match self.parse_mountinfo() {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

        // A) 必须只读的挂载
        let mut ro_viol: Vec<String> = Vec::new();
        for must_ro in &self.ro_required_ro {
            match self.get_mount(&mounts, must_ro) {
                Some(m) if m.opts.contains("ro") => { /* ok */ }
                _ => ro_viol.push(must_ro.clone()),
            }
        }

        // B) 发现所有 rw：只能在白名单里，且必须是 tmpfs/ramfs
        let mut unexpected_rw: Vec<String> = Vec::new();
        let mut non_memfs_allowed: Vec<String> = Vec::new();
        for me in &mounts {
            if self.should_ignore(me) {
                continue;
            }
            if me.opts.contains("rw") {
                if self.ro_allowed_rw.contains(me.mp.as_str()) {
                    if !self.ro_mem_fs.contains(me.fstype.as_str()) {
                        non_memfs_allowed.push(format!("{} (fstype={})", me.mp, me.fstype));
                    }
                } else {
                    unexpected_rw.push(format!("{} (fstype={})", me.mp, me.fstype));
                }
            }
        }

        // C) 根目录写入应 EROFS
        let (ok_w, msg_w) = self.write_probe(PROBE_PATH);
        let root_write_ok = (!ok_w) && msg_w == "EROFS";

        // D) 轻量加固：能力位 & remount
        let caps = self.caps_eff();
        let mut cap_viol: Vec<String> = Vec::new();
        if (caps & CAP_SYS_ADMIN_BIT) != 0 {
            cap_viol.push("CAP_SYS_ADMIN".to_string());
        }
        if (caps & CAP_MKNOD_BIT) != 0 {
            cap_viol.push("CAP_MKNOD".to_string());
        }
        let (remount_blocked, remount_msg) = self.try_remount_root_rw();

        // 总体是否 OK（与 Python 等价）
        let ok = ro_viol.is_empty()  //只读的挂载点必须要是只读
            && unexpected_rw.is_empty()     //没有意外的可写路径
            && non_memfs_allowed.is_empty()   //可写路径里面没有在ro_mem_fs（即允许的挂载点）之外的
            && root_write_ok                 //根路径不可写
            && cap_viol.is_empty()          //容器内没有权限轻易的修改只读
            && remount_blocked;             //尝试修改只读权限失败

        let mut allowed_rw_whitelist: Vec<String> =
            self.ro_allowed_rw.iter().cloned().collect();
        allowed_rw_whitelist.sort();

        let mut required_ro: Vec<String> =
            self.ro_required_ro.iter().cloned().collect();
        required_ro.sort();

        let report = Report {
            ro_violations: ro_viol,  // ro_required_ro 中规定必须是只读的挂载点，哪些没做到就会被记录在这里
            unexpected_rw_mounts: unexpected_rw,  // 不在白名单里的挂载点，却以 rw 挂载，说明出现了额外的可写目录
            allowed_but_not_memfs: non_memfs_allowed,  // 虽然目录在白名单里，但实际挂载的文件系统类型不是 tmpfs/ramfs
            root_write_probe: RootWriteProbe { ok: root_write_ok, need: "EROFS" },  // 尝试在根目录 `/` 写入一个文件，如果报错且 errno=EROFS 才算符合预期
            cap_violations: cap_viol,   // 检查进程的 CapEff（有效能力位），如果还残留了 CAP_SYS_ADMIN 或 CAP_MKNOD 之类的高危权限，就记录下来
            remount_root_blocked: remount_blocked,   // 如果失败（EPERM），说明无法把根目录重新挂成可写 → true
            remount_msg,   // 上一步 remount 命令返回的错误消息，方便调试（例如 "permission denied"）
            allowed_rw_whitelist,   // 允许可写的挂载点白名单（配置中的集合），便于在报告里展示出来
            required_ro,   // 要求必须只读的挂载点集合，便于在报告里展示出来
        };

        (ok, report)
    }

    pub fn watch(&self, period: Duration, grace: u32) -> ! {
        let mut consecutive_fail = 0u32;

        loop {
            let (ok, report) = self.verify_once();

            // 每轮都输出一行 JSON（便于收集到日志/JSONL）
            // 你也可以改成只在失败时输出
            println!("{}", serde_json::to_string(&report).unwrap());

            if ok {
                consecutive_fail = 0;
            } else {
                consecutive_fail += 1;
                if consecutive_fail >= grace {
                    eprintln!("[RO-GUARD] violation detected ({} consecutive)", consecutive_fail);
                    std::process::exit(1);
                }
            }

            thread::sleep(period);
        }
    }
}
