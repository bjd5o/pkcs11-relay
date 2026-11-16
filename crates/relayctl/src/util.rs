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

#[cfg(test)]
mod tests {
    #[test]
    fn dates() {
        assert_eq!(super::utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(super::utc(1_794_744_000), "2026-11-15 12:00 UTC");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00 UTC");
    }
}
