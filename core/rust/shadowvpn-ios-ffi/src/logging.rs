//! os_log-backed logging bridge for the ShadowVPN data plane.
//!
//! ShadowVPN's FFI is far smaller than meow's: there is no embedded proxy
//! engine and no `tracing` graph to forward, so this module is just the oslog
//! sink plus a panic hook. Every `log::{info,warn,error,debug}!` in this crate
//! — and every `svpn_core_log` call from the ObjC NetworkExtension host —
//! reaches Apple's unified log through one `oslog::OsLogger`, viewable with
//! `log stream --predicate 'subsystem == "com.tangzixiang.shadowvpn.PacketTunnel"'`
//! on macOS or in Console while a device is attached.

use std::sync::Once;

static INIT: Once = Once::new();

/// os_log subsystem — the PacketTunnel extension's bundle id, matching the
/// `os_log` subsystem the ObjC `SV*` classes use, so engine + NE lifecycle
/// lines interleave on one timeline.
const OSLOG_SUBSYSTEM: &str = "com.tangzixiang.shadowvpn.PacketTunnel";

/// Initialize the os_log bridge. Idempotent — safe to call from every
/// `svpn_core_init`, which the NE may invoke more than once across restarts.
pub fn init_os_logger() {
    INIT.call_once(|| {
        if let Err(e) = oslog::OsLogger::new(OSLOG_SUBSYSTEM)
            .level_filter(log::LevelFilter::Debug)
            .init()
        {
            // The logger can only fail to install if a global `log` logger was
            // already set; fall back to stderr so we don't lose the reason.
            eprintln!("oslog init failed: {e}");
        }
    });
}

/// Emit an internal lifecycle line through the oslog bridge at `info` level.
/// Used for the crate's own start/stop/keepalive breadcrumbs so they land on
/// the same timeline as engine + NE output.
pub fn bridge_log(msg: &str) {
    log::info!("{msg}");
}

/// Route Rust panics to os_log before the runtime aborts.
///
/// With `panic = "abort"` a panic on a tokio worker takes the whole process
/// down, and NetworkExtension does not capture stderr — so without this hook
/// the iOS crash report shows only a backtrace, never the panic *message*.
/// Installing it once at `svpn_core_init` means any data-plane panic (a bad
/// slice index in the DNS synthesizer, say) leaves a readable os_log line.
/// Idempotent.
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
