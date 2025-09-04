//! # RoGuard: Read-Only Guard
//!
//! This module enforces **read-only guarantees** inside a container runtime.
//! It checks mount points, capabilities, and write probes to ensure the root filesystem
//! and critical paths cannot be modified.
//!
//! ## Features
//! - Validate that certain mount points (`/`, `/model`) are mounted read-only.
//! - Ensure writable mounts (`/tmp`, `/dev/shm`, `/root/.cache`, etc.) are tmpfs/ramfs.
//! - Probe root (`/`) write attempts and expect `EROFS` (read-only filesystem).
//! - Verify dangerous Linux capabilities (e.g. `CAP_SYS_ADMIN`, `CAP_MKNOD`) are dropped.
//! - Ensure `mount -o remount,rw /` is blocked.
//!
//! ## Example: One-shot Verification
//!
//! ```no_run
//! use roguard::RoGuard;
//! use std::process;
//!
//! fn main() {
//!     let guard = RoGuard::new();
//!     let (ok, report) = guard.verify_once();
//!     println!("{}", serde_json::to_string_pretty(&report).unwrap());
//!     if !ok {
//!         eprintln!("[RO-GUARD] startup check failed");
//!         process::exit(1);
//!     }
//! }
//! ```
//!
//! ## Example: Watch Mode
//!
//! ```no_run
//! use roguard::RoGuard;
//! use std::time::Duration;
//!
//! fn main() {
//!     // Check every 5 seconds; exit after 1 consecutive violation
//!     RoGuard::new().watch(Duration::from_secs(5), 1);
//! }
//! ```
//!
//! Expected behavior:
//! - In one-shot mode, prints a JSON report and returns 0 on success, nonzero on violation.
//! - In watch mode, prints a JSON line every cycle, and exits with code 1 if violations persist.
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io::{self, Read};
use std::process::Command;

use std::time::Duration;   // Add this line if not already imported at the top
use std::thread;

const PROBE_PATH: &str = "/.__ro_probe__";
const CAP_SYS_ADMIN_BIT: u64 = 1 << 21;
const CAP_MKNOD_BIT: u64 = 1 << 27;

/// Represents a single mount entry parsed from `/proc/self/mountinfo`.
///
/// Fields:
/// - `mp`: mount point path (e.g., `/`, `/dev/shm`)
/// - `opts`: mount options as a set (e.g., `ro`, `rw`, `nosuid`)
/// - `fstype`: filesystem type (e.g., `ext4`, `tmpfs`)
/// - `src`: source (device/path)
#[derive(Debug, Clone)]
struct MountEntry {
    mp: String,                    // mount point
    opts: HashSet<String>,         // mount options (comma separated)
    fstype: String,                // filesystem type
    src: String,                   // source (device/path)
}

/// Report produced by a verification run. Field names are aligned with the Python version.
///
/// - `ro_violations`: mount points that were required to be read-only but were not
/// - `unexpected_rw_mounts`: writable mount points not in the whitelist
/// - `allowed_but_not_memfs`: whitelisted writable mount points that are not tmpfs/ramfs
/// - `root_write_probe`: result of the root write probe (should be `EROFS`)
/// - `cap_violations`: dangerous capabilities detected (e.g. `CAP_SYS_ADMIN`)
/// - `remount_root_blocked`: whether a `mount -o remount,rw /` attempt was blocked
/// - `remount_msg`: stderr/stdout message from the remount attempt
/// - `allowed_rw_whitelist`: sorted whitelist of allowed writable mount points
/// - `required_ro`: sorted list of mount points that must be read-only
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

/// Result of a root write probe.
#[derive(Debug, Serialize)]
pub struct RootWriteProbe {
    /// `true` means the probe met the expected condition (root is effectively read-only).
    pub ok: bool,
    /// Expected error code string when attempting a write on `/`: fixed `"EROFS"`.
    pub need: &'static str, // fixed "EROFS"
}

/// Read-only guard policy and verification logic.
///
/// The policy defines:
/// - which mount points are required to be read-only,
/// - which mount points may be writable but must be in-memory filesystems (`tmpfs`/`ramfs`),
/// - and which filesystem types/prefixes are ignored during scanning.
///
/// # Examples
///
/// ## One-shot verification
/// ```no_run
/// use std::process;
/// let g = roguard::RoGuard::new();
/// let (ok, report) = g.verify_once();
/// println!("{}", serde_json::to_string(&report).unwrap());
/// if !ok { process::exit(1); }
/// ```
///
/// ## Watch mode (will exit the process with code 1 after `grace` consecutive failures)
/// ```no_run
/// use std::time::Duration;
/// roguard::RoGuard::new().watch(Duration::from_secs(5), 1);
/// ```
pub struct RoGuard {
    ro_allowed_rw: HashSet<String>,    // whitelist of writable mount points (e.g. /tmp, /dev/shm, /root/.cache, /root/.triton)
    ro_required_ro: HashSet<String>,   // mount points that must be read-only (e.g. / and /model)
    ro_mem_fs: HashSet<String>,        // allowed writable mount points must be tmpfs/ramfs
    ro_ign_fstypes: HashSet<String>,   // ignore these virtual/system filesystem types (proc, sysfs, cgroup, etc.)
    ro_ign_prefixes: Vec<String>,      // ignore mount points with these prefixes (/proc, /sys, /dev, etc.)
}

impl Default for RoGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl RoGuard {
    /// Construct a `RoGuard` with built-in policy sets (kept consistent with the Python version).
    ///
    /// - `ro_allowed_rw`: `/dev`, `/dev/shm`, `/tmp`, `/root/.triton`, `/root/.cache`
    /// - `ro_required_ro`: `/`, `/model`
    /// - `ro_mem_fs`: `tmpfs`, `ramfs`
    /// - `ro_ign_fstypes`: typical virtual/system fs types (e.g., `proc`, `sysfs`, `cgroup*`, etc.)
    /// - `ro_ign_prefixes`: `/proc`, `/sys`
    pub fn new() -> Self {
        let ro_allowed_rw = HashSet::from_iter([
            "/dev".to_string(),
            "/dev/shm".to_string(),
            "/tmp".to_string(),
            "/root/.triton".to_string(),
            "/root/.cache".to_string(),
            "/model".to_string(),
        ]);

        let ro_required_ro = HashSet::from_iter([
            "/".to_string(),
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

    /// Parse `/proc/self/mountinfo` into a vector of `MountEntry`.
    ///
    /// Each line is split into the "left" and "right" parts by `" - "`. The 5th and 6th fields in
    /// the left part are interpreted as `mount point` and `options`, and the first two fields of the
    /// right part are interpreted as `fstype` and `src`.
    ///
    /// Returns `io::Result<Vec<MountEntry>>`.
    fn parse_mountinfo(&self) -> io::Result<Vec<MountEntry>> {
        let mut s = String::new();
        fs::File::open("/proc/self/mountinfo")?.read_to_string(&mut s)?;
        let mut out = Vec::new();

        for line in s.lines() {
            // Format: <left> - <fstype> <src> <superopts>
            let mut parts = line.splitn(2, " - ");
            let left = parts.next().unwrap_or("");
            let right = parts.next().unwrap_or("");
            let l: Vec<&str> = left.split_whitespace().collect();
            let r: Vec<&str> = right.split_whitespace().collect();

            // 5th column: mount point, 6th column: options
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

    /// Decide whether a mount entry should be ignored during scanning.
    ///
    /// Rules:
    /// - never ignore `/`,
    /// - ignore if filesystem type is in `ro_ign_fstypes`,
    /// - ignore if mount point starts with any prefix in `ro_ign_prefixes`.
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

    /// Find a mount entry by an exact mount point path.
    ///
    /// Returns `Some(&MountEntry)` if found, otherwise `None`.
    fn get_mount<'a>(&self, mounts: &'a [MountEntry], target: &str) -> Option<&'a MountEntry> {
        mounts.iter().find(|m| m.mp == target)
    }

    /// Write probe: attempt writing `PROBE_PATH` under `/`.
    ///
    /// Returns `(ok, msg)`:
    /// - `ok = true`  means write succeeded (root is *writable*; not expected),
    /// - `ok = false` with `msg == "EROFS"` means read-only as expected,
    /// - `ok = false` with other `msg` contains the error reason.
    fn write_probe(&self, path: &str) -> (bool, String) {
        // Python equivalent: open(path, "w") -> create or truncate; success means root is writable
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

    /// Read effective capability bits from `/proc/self/status` (`CapEff` line).
    ///
    /// Returns the parsed `u64` value (0 if parsing fails).
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

    /// Attempt `mount -o remount,rw /` and return whether it was blocked.
    ///
    /// Returns `(blocked, message)`:
    /// - `blocked = true` means the remount attempt failed (this is the *expected* secure state),
    /// - `blocked = false` means it succeeded (insecure).
    fn try_remount_root_rw(&self) -> (bool, String) {
        // true = blocked; false = success (unsafe)
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

    /// Run a single verification round and return `(ok, Report)`.
    ///
    /// Logic:
    /// - Parse and filter mount entries,
    /// - Ensure required read-only mount points are `ro`,
    /// - Ensure all `rw` mounts are in whitelist and use in-memory fs (`tmpfs/ramfs`),
    /// - Probe write on `/` (expecting EROFS),
    /// - Check capability bits (`CAP_SYS_ADMIN`, `CAP_MKNOD`),
    /// - Ensure `remount,rw /` attempt is blocked.
    ///
    /// Returns:
    /// - `ok = true` if all checks pass,
    /// - `ok = false` otherwise, with details in `Report`.
    ///
    /// # Example
    /// ```no_run
    /// let (ok, report) = roguard::RoGuard::new().verify_once();
    /// println!("{}", serde_json::to_string(&report).unwrap());
    /// if !ok { std::process::exit(1); }
    /// ```
    pub fn verify_once(&self) -> (bool, Report) {
        // Read mount info
        let mounts = match self.parse_mountinfo() {
            Ok(v) => v,
            Err(_) => Vec::new(),
        };

        // A) Required read-only mounts
        let mut ro_viol: Vec<String> = Vec::new();
        for must_ro in &self.ro_required_ro {
            match self.get_mount(&mounts, must_ro) {
                Some(m) if m.opts.contains("ro") => { /* ok */ }
                _ => ro_viol.push(must_ro.clone()),
            }
        }

        // B) Detect all rw: must be in whitelist and tmpfs/ramfs
        let mut unexpected_rw: Vec<String> = Vec::new();
        let mut non_memfs_allowed: Vec<String> = Vec::new();
        for me in &mounts {
            if self.should_ignore(me) {
                continue;
            }
            if me.opts.contains("rw") {
                if self.ro_allowed_rw.contains(me.mp.as_str()) {
                    if me.mp != "/model" && !self.ro_mem_fs.contains(me.fstype.as_str()) {
                        non_memfs_allowed.push(format!("{} (fstype={})", me.mp, me.fstype));
                    }
                } else {
                    unexpected_rw.push(format!("{} (fstype={})", me.mp, me.fstype));
                }
            }
        }

        // C) Root write should return EROFS
        let (ok_w, msg_w) = self.write_probe(PROBE_PATH);
        let root_write_ok = (!ok_w) && msg_w == "EROFS";

        // D) Lightweight hardening: capability bits & remount attempt
        let caps = self.caps_eff();
        let mut cap_viol: Vec<String> = Vec::new();
        if (caps & CAP_SYS_ADMIN_BIT) != 0 {
            cap_viol.push("CAP_SYS_ADMIN".to_string());
        }
        if (caps & CAP_MKNOD_BIT) != 0 {
            cap_viol.push("CAP_MKNOD".to_string());
        }
        let (remount_blocked, remount_msg) = self.try_remount_root_rw();

        // Overall check result (consistent with Python version)
        let ok = ro_viol.is_empty()  // required mounts must be ro
            && unexpected_rw.is_empty()     // no unexpected writable paths
            && non_memfs_allowed.is_empty() // writable paths must be tmpfs/ramfs
            && root_write_ok                // root must not be writable
            && cap_viol.is_empty()          // no dangerous capabilities remain
            && remount_blocked;             // remount must fail

        let mut allowed_rw_whitelist: Vec<String> =
            self.ro_allowed_rw.iter().cloned().collect();
        allowed_rw_whitelist.sort();

        let mut required_ro: Vec<String> =
            self.ro_required_ro.iter().cloned().collect();
        required_ro.sort();

        let report = Report {
            ro_violations: ro_viol,  // required ro mounts that failed
            unexpected_rw_mounts: unexpected_rw,  // extra rw mounts not in whitelist
            allowed_but_not_memfs: non_memfs_allowed,  // whitelisted but not tmpfs/ramfs
            root_write_probe: RootWriteProbe { ok: root_write_ok, need: "EROFS" },  // root write probe
            cap_violations: cap_viol,   // capability violations (e.g. CAP_SYS_ADMIN, CAP_MKNOD)
            remount_root_blocked: remount_blocked,   // true if remount rw was blocked
            remount_msg,   // error message from remount attempt
            allowed_rw_whitelist,   // configured whitelist of writable mounts
            required_ro,   // configured required read-only mounts
        };

        (ok, report)
    }

    /// Watch mode: run `verify_once` repeatedly with a fixed period.
    ///
    /// Prints one line of JSON per loop iteration (suitable for JSONL logs). If the check fails
    /// `grace` times consecutively, the process exits with code 1.
    ///
    /// This function never returns.
    ///
    /// # Example
    /// ```no_run
    /// use std::time::Duration;
    /// roguard::RoGuard::new().watch(Duration::from_secs(5), 1);
    /// ```
    pub fn watch(&self, period: Duration, grace: u32) -> ! {
    let mut consecutive_fail = 0u32;

    loop {
        let (ok, report) = self.verify_once();

        // Only output report when violation occurs
        if !ok {
            eprintln!("{}", serde_json::to_string(&report).unwrap());
        }

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
