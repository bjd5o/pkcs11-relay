//! Small helpers: time, PEM, prompts.

use std::io::{BufRead, IsTerminal, Write};
use std::path::Path;

use relay_core::PublicKey;
use zeroize::Zeroizing;

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `YYYY-MM-DD HH:MM UTC` for a Unix time (civil-from-days, H. Hinnant).
pub fn utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60
    )
}

/// Read a public key from a PEM (`PUBLIC KEY`) or DER SubjectPublicKeyInfo file.
pub fn read_public_key(path: &Path) -> Result<PublicKey, String> {
    let data = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let der = if data.starts_with(b"-----BEGIN") {
        let (label, der) = p256::pkcs8::der::pem::decode_vec(&data)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if label != "PUBLIC KEY" {
            return Err(format!(
                "{}: expected a PUBLIC KEY PEM block, found {label}",
                path.display()
            ));
        }
        der
    } else {
        data
    };
    PublicKey::from_spki(&der).map_err(|e| format!("{}: {e}", path.display()))
}

pub fn public_key_pem(pk: &PublicKey) -> String {
    p256::pkcs8::der::pem::encode_string("PUBLIC KEY", p256::pkcs8::LineEnding::LF, pk.spki())
        .expect("PEM")
}

pub fn write(path: &Path, data: impl AsRef<[u8]>) -> Result<(), String> {
    std::fs::write(path, data).map_err(|e| format!("{}: {e}", path.display()))
}

/// Read a secret from the terminal without echo.
pub fn prompt_secret(prompt: &str) -> Result<Zeroizing<String>, String> {
    rpassword::prompt_password(prompt)
        .map(Zeroizing::new)
        .map_err(|e| format!("reading {prompt}: {e}"))
}

/// Ask for an exact phrase on an interactive terminal; refuses when stdin is not a TTY.
pub fn confirm_phrase(question: &str, phrase: &str) -> Result<bool, String> {
    if !std::io::stdin().is_terminal() {
        return Err("confirmation needs an interactive terminal".into());
    }
    eprint!("{question}\nType `{phrase}` to continue: ");
    std::io::stderr().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']) == phrase)
}

/// Parse `7d`, `12h`, `30m`, `90s` or plain seconds.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    let (num, mult) = match s.char_indices().last() {
        Some((i, 'd')) => (&s[..i], 86_400),
        Some((i, 'h')) => (&s[..i], 3_600),
        Some((i, 'm')) => (&s[..i], 60),
        Some((i, 's')) => (&s[..i], 1),
        _ => (s, 1),
    };
    num.parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(mult))
        .filter(|n| *n > 0)
        .ok_or_else(|| format!("`{s}` is not a duration like 7d, 12h, 30m or 90s"))
}

/// A duration in the largest whole unit: `7d`, `36h`, `90m`, `45s`.
pub fn duration(secs: u64) -> String {
    for (unit, n) in [("d", 86_400), ("h", 3_600), ("m", 60)] {
        if secs.is_multiple_of(n) && secs >= n {
            return format!("{}{unit}", secs / n);
        }
    }
    format!("{secs}s")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_794_744_000), "2026-11-15 12:00 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00 UTC");
    }

    #[test]
    fn durations_round_trip() {
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert_eq!(parse_duration("12h").unwrap(), 43_200);
        assert_eq!(parse_duration("90").unwrap(), 90);
        assert!(parse_duration("0d").is_err());
        assert!(parse_duration("x").is_err());
        assert_eq!(duration(604_800), "7d");
        assert_eq!(duration(5_400), "90m");
        assert_eq!(duration(45), "45s");
    }
}
