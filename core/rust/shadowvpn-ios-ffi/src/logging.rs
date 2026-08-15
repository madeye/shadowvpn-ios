//! Logging for the ShadowVPN data plane.
//!
//! Every `log::{info,warn,error,debug}!` in this crate — and every
//! `svpn_core_log` call from the ObjC NetworkExtension host — goes to Apple's
//! unified log (os_log) via one global logger, viewable with
//! `log stream --predicate 'subsystem == "com.tangzixiang.shadowvpn.PacketTunnel"'`
//! or `idevicesyslog`.
//!
//! In addition, every **info-or-higher** record is mirrored to a small,
//! line-based file in the App Group container (`logs/svpn-tunnel.log`, the path
//! the host hands us via [`set_log_file`]). The app's Log view tails that file —
//! the NetworkExtension's own `OSLogStore` is not readable from the app. Debug/
//! trace records (e.g. the 2 Hz traffic pump) stay in os_log only so the file
//! stays small; the file is rotated to `.1` once it crosses [`MAX_LOG_BYTES`].

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Log, Metadata, Record};
use oslog::OsLog;

static INIT: Once = Once::new();

/// os_log subsystem — the PacketTunnel extension's bundle id, matching the
/// `os_log` subsystem the ObjC `SV*` classes use, so engine + NE lifecycle
/// lines interleave on one timeline.
const OSLOG_SUBSYSTEM: &str = "com.tangzixiang.shadowvpn.PacketTunnel";

/// Rotate the mirrored log file to `<name>.1` once it grows past this.
const MAX_LOG_BYTES: u64 = 512 * 1024;

/// Marker file (in the `logs/` dir) recording that the one-time purge of
/// pre-privacy-fix log files has run. Logs written before flow-detail logging
/// became opt-in (#18) contain DNS names / TLS SNI / HTTP hosts, so the first
/// launch of a build with this code deletes the current and rotated files
/// instead of carrying that browsing history forward.
const PURGE_MARKER: &str = ".flow-history-purged-v1";

/// Flow-detail diagnostics deadline, epoch seconds. `0` = disabled (the
/// default). Ingress only inspects and logs per-flow destinations (DNS name /
/// TLS SNI / HTTP host) while `now < deadline`, so the mode self-expires
/// without a timer (#18).
static FLOW_DIAG_UNTIL: AtomicU64 = AtomicU64::new(0);

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Enable flow-detail diagnostics for `secs` seconds from now; `0` disables
/// immediately. Called from `svpn_core_set_flow_diagnostics`.
pub fn set_flow_diagnostics_secs(secs: u32) {
    if secs == 0 {
        FLOW_DIAG_UNTIL.store(0, Ordering::Relaxed);
        log::info!("flow diagnostics off");
    } else {
        let until = now_epoch_secs().saturating_add(u64::from(secs));
        FLOW_DIAG_UNTIL.store(until, Ordering::Relaxed);
        log::info!("flow diagnostics on for {secs}s");
    }
}

/// Whether the ingress loop should inspect packets and log flow destinations.
/// False once the opt-in window has elapsed.
pub fn flow_diagnostics_active() -> bool {
    let until = FLOW_DIAG_UNTIL.load(Ordering::Relaxed);
    until != 0 && now_epoch_secs() < until
}

/// Append handle for the shared log file, installed by [`set_log_file`]. `None`
/// until the host sets the home dir.
fn log_file() -> &'static Mutex<Option<File>> {
    static F: OnceLock<Mutex<Option<File>>> = OnceLock::new();
    F.get_or_init(|| Mutex::new(None))
}

/// Global logger: fans every record out to os_log, and info+ to the shared file.
struct Logger {
    os: OsLog,
}

impl Log for Logger {
    fn enabled(&self, m: &Metadata) -> bool {
        m.level() <= Level::Debug
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let msg = format!("{}", record.args());
        self.os.with_level(record.level().into(), &msg);

        // Mirror info+ to the file the app's Log view tails.
        if record.level() <= Level::Info {
            if let Ok(mut guard) = log_file().lock() {
                if let Some(f) = guard.as_mut() {
                    let secs = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    // "HH:MM:SS LEVEL message" (UTC). The app sniffs the LEVEL
                    // token for row tinting; it doesn't require a strict format.
                    let _ = writeln!(
                        f,
                        "{:02}:{:02}:{:02} {:<5} {}",
                        (secs / 3600) % 24,
                        (secs / 60) % 60,
                        secs % 60,
                        record.level(),
                        msg,
                    );
                }
            }
        }
    }

    fn flush(&self) {}
}

/// Initialize logging. Idempotent — safe to call from every `svpn_core_init`,
/// which the NE may invoke more than once across restarts.
pub fn init_os_logger() {
    INIT.call_once(|| {
        let logger = Logger {
            os: OsLog::new(OSLOG_SUBSYSTEM, "core"),
        };
        if let Err(e) = log::set_boxed_logger(Box::new(logger)) {
            // Only fails if a global logger was already set.
            eprintln!("svpn logger init failed: {e}");
            return;
        }
        log::set_max_level(LevelFilter::Debug);
    });
}

/// Point the file mirror at `<home_dir>/logs/svpn-tunnel.log`. Creates the
/// directory, rotates an oversized existing file to `.1`, and opens the file for
/// append. Called from `svpn_core_set_home_dir`. No-op on an empty path.
pub fn set_log_file(home_dir: &str) {
    if home_dir.is_empty() {
        return;
    }
    let dir = Path::new(home_dir).join("logs");
    if fs::create_dir_all(&dir).is_err() {
        return;
    }
    purge_pre_privacy_logs(&dir);
    let path = dir.join("svpn-tunnel.log");
    if let Ok(meta) = fs::metadata(&path) {
        if meta.len() > MAX_LOG_BYTES {
            let _ = fs::rename(&path, dir.join("svpn-tunnel.log.1"));
        }
    }
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => {
            if let Ok(mut guard) = log_file().lock() {
                *guard = Some(f);
            }
        }
        Err(e) => eprintln!("svpn log file open failed: {e}"),
    }
}

/// One-time deletion of log files written before flow-detail logging became
/// opt-in (#18): those files can contain a browsing-history record (DNS / SNI /
/// HTTP hosts logged at info by default), so the first run of a fixed build
/// deletes the current and rotated files rather than carrying them forward.
/// Idempotent via a marker file in the same directory.
fn purge_pre_privacy_logs(dir: &Path) {
    let marker = dir.join(PURGE_MARKER);
    if marker.exists() {
        return;
    }
    let _ = fs::remove_file(dir.join("svpn-tunnel.log"));
    let _ = fs::remove_file(dir.join("svpn-tunnel.log.1"));
    let _ = File::create(&marker);
}

/// Emit an internal lifecycle line at `info` level (so it reaches both os_log
/// and the mirrored file).
pub fn bridge_log(msg: &str) {
    log::info!("{msg}");
}

/// Route Rust panics to the logger before the runtime aborts.
///
/// With `panic = "abort"` a panic on a tokio worker takes the whole process
/// down, and NetworkExtension does not capture stderr — so without this hook
/// the iOS crash report shows only a backtrace, never the panic *message*.
/// Installing it once at `svpn_core_init` means any data-plane panic leaves a
/// readable line in os_log and the mirrored file. Idempotent.
pub fn install_panic_hook() {
    static INSTALLED: Once = Once::new();
    INSTALLED.call_once(|| {
        let default_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let location = info
                .location()
                .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
                .unwrap_or_else(|| "<unknown>".to_string());
            let payload = info.payload();
            let msg = if let Some(s) = payload.downcast_ref::<&str>() {
                (*s).to_string()
            } else if let Some(s) = payload.downcast_ref::<String>() {
                s.clone()
            } else {
                "<non-string panic payload>".to_string()
            };
            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("<unnamed>");
            log::error!("rust panic in thread '{thread_name}' at {location}: {msg}");
            default_hook(info);
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One test drives the whole enable → expire → disable sequence because
    /// `FLOW_DIAG_UNTIL` is process-global; separate `#[test]` fns would race.
    #[test]
    fn flow_diagnostics_default_off_opt_in_and_expiring() {
        // Default: off — ordinary traffic must not be inspected (#18).
        assert!(!flow_diagnostics_active());

        // Explicit opt-in turns it on for the window.
        set_flow_diagnostics_secs(60);
        assert!(flow_diagnostics_active());

        // Explicit disable turns it off immediately.
        set_flow_diagnostics_secs(0);
        assert!(!flow_diagnostics_active());

        // A deadline in the past reads as expired, without any timer firing.
        FLOW_DIAG_UNTIL.store(now_epoch_secs().saturating_sub(1), Ordering::Relaxed);
        assert!(!flow_diagnostics_active());
        FLOW_DIAG_UNTIL.store(0, Ordering::Relaxed);
    }

    #[test]
    fn purge_deletes_old_logs_exactly_once() {
        let dir = std::env::temp_dir().join(format!(
            "svpn-purge-test-{}-{}",
            std::process::id(),
            now_epoch_secs()
        ));
        fs::create_dir_all(&dir).unwrap();
        let current = dir.join("svpn-tunnel.log");
        let rotated = dir.join("svpn-tunnel.log.1");
        fs::write(&current, "flow → TLS SNI example.com\n").unwrap();
        fs::write(&rotated, "flow → DNS A example.org\n").unwrap();

        // First run deletes both files and drops the marker.
        purge_pre_privacy_logs(&dir);
        assert!(!current.exists(), "current log must be purged");
        assert!(!rotated.exists(), "rotated log must be purged");
        assert!(dir.join(PURGE_MARKER).exists());

        // Later runs leave newly written (post-fix) logs alone.
        fs::write(&current, "lifecycle line\n").unwrap();
        purge_pre_privacy_logs(&dir);
        assert!(current.exists(), "post-purge logs must survive restarts");

        let _ = fs::remove_dir_all(&dir);
    }
}
