//! Minimal logging to stderr or a file. Never pass PINs, keys or operation results here;
//! requests and their outcomes may be logged.

use std::io::Write;
use std::sync::Mutex;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Error = 0,
    Warn = 1,
    Info = 2,
    Debug = 3,
}

struct Logger {
    level: Level,
    file: Option<std::fs::File>,
}

static LOGGER: Mutex<Option<Logger>> = Mutex::new(None);

pub fn init(level: Option<&str>, path: Option<&std::path::Path>) {
    let level = match level.unwrap_or("warn") {
        "error" => Level::Error,
        "info" => Level::Info,
        "debug" => Level::Debug,
        _ => Level::Warn,
    };
    let file = path.and_then(|p| {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(p)
            .ok()
    });
    *LOGGER.lock().unwrap_or_else(|e| e.into_inner()) = Some(Logger { level, file });
}

fn write(level: Level, tag: &str, msg: &str) {
    let mut g = LOGGER.lock().unwrap_or_else(|e| e.into_inner());
    let enabled = g
        .as_ref()
        .map(|l| level <= l.level)
        .unwrap_or(level <= Level::Warn);
    if !enabled {
        return;
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let line = format!("{t} relay-pkcs11 {tag}: {msg}\n");
    match g.as_mut().and_then(|l| l.file.as_mut()) {
        Some(f) => {
            let _ = f.write_all(line.as_bytes());
        }
        None => {
            let _ = std::io::stderr().write_all(line.as_bytes());
        }
    }
}

pub fn error(msg: &str) {
    write(Level::Error, "ERROR", msg)
}
pub fn warn(msg: &str) {
    write(Level::Warn, "WARN", msg)
}
pub fn info(msg: &str) {
    write(Level::Info, "INFO", msg)
}
pub fn debug(msg: &str) {
    write(Level::Debug, "DEBUG", msg)
}
