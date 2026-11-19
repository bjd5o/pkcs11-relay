//! SQLite (WAL) storage for the client and device registries and the audit log. Pending
//! requests and pairings live in memory (spec: "pending requests may be lost").

use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::{Row, SqlitePool};

pub type Db = SqlitePool;

const SCHEMA: &[&str] = &[
    "CREATE TABLE IF NOT EXISTS clients (
        client_id TEXT PRIMARY KEY,
        public_key BLOB NOT NULL,
        fingerprint TEXT NOT NULL UNIQUE,
        host TEXT NOT NULL,
        approved_keys TEXT NOT NULL,
        approved_by TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        grant_bytes BLOB NOT NULL,
        grant_seq INTEGER NOT NULL,
        last_seen INTEGER NOT NULL)",
    "CREATE TABLE IF NOT EXISTS devices (
        device_id TEXT PRIMARY KEY,
        device_key BLOB NOT NULL,
        fingerprint TEXT NOT NULL UNIQUE,
        attestation BLOB NOT NULL,
        keys TEXT NOT NULL,
        push TEXT NOT NULL,
        last_seen INTEGER NOT NULL,
        created_at INTEGER NOT NULL,
        auth_key BLOB NOT NULL,
        auth_fingerprint TEXT NOT NULL UNIQUE,
        setup_link_id TEXT,
        admin_key BLOB,
        admin_fingerprint TEXT UNIQUE)",
    "CREATE TABLE IF NOT EXISTS audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ts INTEGER NOT NULL,
        event TEXT NOT NULL,
        client_id TEXT,
        device_id TEXT,
        req_id TEXT,
        key_fingerprint TEXT,
        op TEXT,
        mechanism TEXT,
        host TEXT,
        purpose TEXT,
        consumer TEXT,
        input_sha256 TEXT,
        status TEXT,
        reason TEXT,
        detail TEXT,
        request BLOB,
        response BLOB)",
    "CREATE INDEX IF NOT EXISTS audit_ts ON audit (ts)",
    // Setup links already used to admit a device (wire-format §11.3), by SHA-256 of their
    // signed bytes. Kept when the device is revoked.
    "CREATE TABLE IF NOT EXISTS used_setup_links (
        link_id TEXT PRIMARY KEY,
        device_id TEXT NOT NULL,
        exp INTEGER NOT NULL,
        used_at INTEGER NOT NULL)",
    // Revocations of the manifest signer the relay has seen (wire-format §11.4). Permanent for
    // that key.
    "CREATE TABLE IF NOT EXISTS signer_revocations (
        fingerprint TEXT PRIMARY KEY,
        revoked_at INTEGER NOT NULL,
        reason TEXT NOT NULL,
        seen_at INTEGER NOT NULL)",
    // Client revocations signed by an attest key (wire-format §12.3), served until `live_until`
    // (the end of the last grant they cancel). Keyed by the exact bytes' hash.
    "CREATE TABLE IF NOT EXISTS client_revocations (
        id TEXT PRIMARY KEY,
        client_fingerprint TEXT NOT NULL,
        seq INTEGER NOT NULL,
        revocation BLOB NOT NULL,
        live_until INTEGER NOT NULL,
        created_at INTEGER NOT NULL)",
];

pub async fn open(data_dir: &Path) -> Result<Db, String> {
    std::fs::create_dir_all(data_dir)
        .map_err(|e| format!("creating {}: {e}", data_dir.display()))?;
    let url = format!("sqlite://{}", data_dir.join("relay.db").display());
    let opts = SqliteConnectOptions::from_str(&url)
        .map_err(|e| e.to_string())?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await
        .map_err(|e| e.to_string())?;
    for stmt in SCHEMA {
        sqlx::query(stmt)
            .execute(&pool)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(pool)
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientRecord {
    pub client_id: String,
    #[serde(skip)]
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    pub host: String,
    pub approved_keys: Vec<String>,
    pub approved_by: String,
    pub created_at: i64,
    /// The latest client grant (wire-format §12.1), as the device signed it.
    #[serde(skip)]
    pub grant: Vec<u8>,
    /// The grant's `seq`.
    pub grant_seq: u64,
    pub last_seen: i64,
}

/// A hardware key a device says it can operate. Untrusted: a hint for discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvertisedKey {
    pub fingerprint: String,
    /// Base64 DER SPKI.
    pub public_key: String,
    pub token: String,
}

/// How to ring a device. APNs and FCM senders arrive in milestones 5 and 6.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum PushTarget {
    #[default]
    None,
    Ntfy {
        topic: String,
    },
    Apns {
        token: String,
    },
    Fcm {
        token: String,
    },
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceRecord {
    pub device_id: String,
    #[serde(skip)]
    pub device_key: Vec<u8>,
    pub fingerprint: String,
    /// The key that signs this device's relay calls: a separate key the device key vouched
    /// for (wire-format §8.4), or the device key itself.
    #[serde(skip)]
    pub auth_key: Vec<u8>,
    pub auth_fingerprint: String,
    /// The biometric-gated key that signs this device's admin calls (wire-format §8.5), if it
    /// registered one.
    #[serde(skip)]
    pub admin_key: Option<Vec<u8>>,
    pub admin_fingerprint: Option<String>,
    #[serde(skip)]
    pub attestation: Vec<u8>,
    pub keys: Vec<AdvertisedKey>,
    pub push: PushTarget,
    pub last_seen: i64,
    pub created_at: i64,
    /// SHA-256 of the signed bytes of the setup link that admitted this device, if any.
    pub setup_link_id: Option<String>,
}

impl DeviceRecord {
    pub fn advertises(&self, fp: &str) -> bool {
        self.keys.iter().any(|k| k.fingerprint == fp)
    }
}

fn client_from_row(r: &sqlx::sqlite::SqliteRow) -> ClientRecord {
    ClientRecord {
        client_id: r.get("client_id"),
        public_key: r.get("public_key"),
        fingerprint: r.get("fingerprint"),
        host: r.get("host"),
        approved_keys: serde_json::from_str(r.get::<&str, _>("approved_keys")).unwrap_or_default(),
        approved_by: r.get("approved_by"),
        created_at: r.get("created_at"),
        grant: r.get("grant_bytes"),
        grant_seq: r.get::<i64, _>("grant_seq") as u64,
        last_seen: r.get("last_seen"),
    }
}

fn device_from_row(r: &sqlx::sqlite::SqliteRow) -> DeviceRecord {
    DeviceRecord {
        device_id: r.get("device_id"),
        device_key: r.get("device_key"),
        fingerprint: r.get("fingerprint"),
        auth_key: r.get("auth_key"),
        auth_fingerprint: r.get("auth_fingerprint"),
        admin_key: r.get("admin_key"),
        admin_fingerprint: r.get("admin_fingerprint"),
        attestation: r.get("attestation"),
        keys: serde_json::from_str(r.get::<&str, _>("keys")).unwrap_or_default(),
        push: serde_json::from_str(r.get::<&str, _>("push")).unwrap_or_default(),
        last_seen: r.get("last_seen"),
        created_at: r.get("created_at"),
        setup_link_id: r.get("setup_link_id"),
    }
}

type R<T> = Result<T, sqlx::Error>;

pub async fn client_by_fingerprint(db: &Db, fp: &str) -> R<Option<ClientRecord>> {
    Ok(sqlx::query("SELECT * FROM clients WHERE fingerprint = ?")
        .bind(fp)
        .fetch_optional(db)
        .await?
        .as_ref()
        .map(client_from_row))
}

pub async fn client_by_id(db: &Db, id: &str) -> R<Option<ClientRecord>> {
    Ok(sqlx::query("SELECT * FROM clients WHERE client_id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .as_ref()
        .map(client_from_row))
}

pub async fn insert_client(db: &Db, c: &ClientRecord) -> R<()> {
    sqlx::query(
        "INSERT INTO clients (client_id, public_key, fingerprint, host, approved_keys, approved_by, created_at,
           grant_bytes, grant_seq, last_seen)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&c.client_id)
    .bind(&c.public_key)
    .bind(&c.fingerprint)
    .bind(&c.host)
    .bind(serde_json::to_string(&c.approved_keys).expect("json"))
    .bind(&c.approved_by)
    .bind(c.created_at)
    .bind(&c.grant)
    .bind(c.grant_seq as i64)
    .bind(c.last_seen)
    .execute(db)
    .await?;
    Ok(())
}

/// Replace a client's grant and routable keys, only if `seq` is above the stored one. Returns
/// whether it replaced.
pub async fn replace_grant(
    db: &Db,
    client_id: &str,
    grant: &[u8],
    seq: u64,
    keys: &[String],
) -> R<bool> {
    Ok(sqlx::query(
        "UPDATE clients SET grant_bytes = ?, grant_seq = ?, approved_keys = ?
         WHERE client_id = ? AND grant_seq < ?",
    )
    .bind(grant)
    .bind(seq as i64)
    .bind(serde_json::to_string(keys).expect("json"))
    .bind(client_id)
    .bind(seq as i64)
    .execute(db)
    .await?
    .rows_affected()
        > 0)
}

pub async fn touch_client(db: &Db, id: &str, now: i64) -> R<()> {
    sqlx::query("UPDATE clients SET last_seen = ? WHERE client_id = ?")
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

/// A stored client revocation.
#[derive(Debug, Clone)]
pub struct RevocationRecord {
    pub client_fingerprint: String,
    pub seq: u64,
    pub revocation: Vec<u8>,
    pub live_until: u64,
}

/// Store a revocation and delete the client it names, in one transaction.
pub async fn revoke_client(db: &Db, r: &RevocationRecord, now: u64) -> R<()> {
    use sha2::Digest as _;
    let id = hex::encode(sha2::Sha256::digest(&r.revocation));
    let mut tx = db.begin().await?;
    sqlx::query(
        "INSERT INTO client_revocations (id, client_fingerprint, seq, revocation, live_until, created_at)
         VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO NOTHING",
    )
    .bind(&id)
    .bind(&r.client_fingerprint)
    .bind(r.seq as i64)
    .bind(&r.revocation)
    .bind(r.live_until as i64)
    .bind(now as i64)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM clients WHERE fingerprint = ?")
        .bind(&r.client_fingerprint)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Revocations still live at `now` (wire-format §12.3), oldest first.
pub async fn live_revocations(db: &Db, now: u64) -> R<Vec<RevocationRecord>> {
    Ok(sqlx::query(
        "SELECT * FROM client_revocations WHERE live_until >= ? ORDER BY created_at, id",
    )
    .bind(now as i64)
    .fetch_all(db)
    .await?
    .iter()
    .map(|r| RevocationRecord {
        client_fingerprint: r.get("client_fingerprint"),
        seq: r.get::<i64, _>("seq") as u64,
        revocation: r.get("revocation"),
        live_until: r.get::<i64, _>("live_until") as u64,
    })
    .collect())
}

/// Whether a live revocation names this client key.
pub async fn client_key_revoked(db: &Db, fingerprint: &str, now: u64) -> R<bool> {
    let r: Option<(String,)> = sqlx::query_as(
        "SELECT id FROM client_revocations WHERE client_fingerprint = ? AND live_until >= ? LIMIT 1",
    )
    .bind(fingerprint)
    .bind(now as i64)
    .fetch_optional(db)
    .await?;
    Ok(r.is_some())
}

/// Forget revocations whose cancelled grants have all expired.
pub async fn prune_revocations(db: &Db, before: u64) -> R<u64> {
    Ok(
        sqlx::query("DELETE FROM client_revocations WHERE live_until < ?")
            .bind(before as i64)
            .execute(db)
            .await?
            .rows_affected(),
    )
}

pub async fn list_clients(db: &Db) -> R<Vec<ClientRecord>> {
    Ok(sqlx::query("SELECT * FROM clients ORDER BY client_id")
        .fetch_all(db)
        .await?
        .iter()
        .map(client_from_row)
        .collect())
}

pub async fn delete_client(db: &Db, id: &str) -> R<bool> {
    Ok(sqlx::query("DELETE FROM clients WHERE client_id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected()
        > 0)
}

/// The device whose relay-auth key has this fingerprint.
pub async fn device_by_auth_fingerprint(db: &Db, fp: &str) -> R<Option<DeviceRecord>> {
    Ok(
        sqlx::query("SELECT * FROM devices WHERE auth_fingerprint = ?")
            .bind(fp)
            .fetch_optional(db)
            .await?
            .as_ref()
            .map(device_from_row),
    )
}

/// The device whose admin-auth key has this fingerprint.
pub async fn device_by_admin_fingerprint(db: &Db, fp: &str) -> R<Option<DeviceRecord>> {
    Ok(
        sqlx::query("SELECT * FROM devices WHERE admin_fingerprint = ?")
            .bind(fp)
            .fetch_optional(db)
            .await?
            .as_ref()
            .map(device_from_row),
    )
}

pub async fn device_by_id(db: &Db, id: &str) -> R<Option<DeviceRecord>> {
    Ok(sqlx::query("SELECT * FROM devices WHERE device_id = ?")
        .bind(id)
        .fetch_optional(db)
        .await?
        .as_ref()
        .map(device_from_row))
}

pub async fn upsert_device(db: &Db, d: &DeviceRecord) -> R<()> {
    sqlx::query(
        "INSERT INTO devices (device_id, device_key, fingerprint, auth_key, auth_fingerprint, admin_key, admin_fingerprint,
           attestation, keys, push, last_seen, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT(device_id) DO UPDATE SET attestation = excluded.attestation, keys = excluded.keys,
           push = excluded.push, last_seen = excluded.last_seen,
           auth_key = excluded.auth_key, auth_fingerprint = excluded.auth_fingerprint,
           admin_key = excluded.admin_key, admin_fingerprint = excluded.admin_fingerprint",
    )
    .bind(&d.device_id)
    .bind(&d.device_key)
    .bind(&d.fingerprint)
    .bind(&d.auth_key)
    .bind(&d.auth_fingerprint)
    .bind(&d.admin_key)
    .bind(&d.admin_fingerprint)
    .bind(&d.attestation)
    .bind(serde_json::to_string(&d.keys).expect("json"))
    .bind(serde_json::to_string(&d.push).expect("json"))
    .bind(d.last_seen)
    .bind(d.created_at)
    .execute(db)
    .await?;
    Ok(())
}

/// Why a first registration was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum AdmitError {
    /// The setup link was used before.
    LinkUsed,
    /// Another registration took the device id first.
    DeviceIdTaken,
}

/// Admit a new device with the setup link that names it: record the link as used and insert
/// the device, in one transaction (wire-format §11.3).
pub async fn admit_device(db: &Db, d: &DeviceRecord, link_exp: u64) -> R<Result<(), AdmitError>> {
    let link_id = d.setup_link_id.as_deref().unwrap_or_default();
    let mut tx = db.begin().await?;
    let used: Option<(String,)> =
        sqlx::query_as("SELECT link_id FROM used_setup_links WHERE link_id = ?")
            .bind(link_id)
            .fetch_optional(&mut *tx)
            .await?;
    if used.is_some() {
        return Ok(Err(AdmitError::LinkUsed));
    }
    let taken: Option<(String,)> =
        sqlx::query_as("SELECT device_id FROM devices WHERE device_id = ?")
            .bind(&d.device_id)
            .fetch_optional(&mut *tx)
            .await?;
    if taken.is_some() {
        return Ok(Err(AdmitError::DeviceIdTaken));
    }
    sqlx::query(
        "INSERT INTO used_setup_links (link_id, device_id, exp, used_at) VALUES (?, ?, ?, ?)",
    )
    .bind(link_id)
    .bind(&d.device_id)
    .bind(link_exp as i64)
    .bind(d.created_at)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "INSERT INTO devices (device_id, device_key, fingerprint, auth_key, auth_fingerprint, admin_key, admin_fingerprint,
           attestation, keys, push, last_seen, created_at, setup_link_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(&d.device_id)
    .bind(&d.device_key)
    .bind(&d.fingerprint)
    .bind(&d.auth_key)
    .bind(&d.auth_fingerprint)
    .bind(&d.admin_key)
    .bind(&d.admin_fingerprint)
    .bind(&d.attestation)
    .bind(serde_json::to_string(&d.keys).expect("json"))
    .bind(serde_json::to_string(&d.push).expect("json"))
    .bind(d.last_seen)
    .bind(d.created_at)
    .bind(&d.setup_link_id)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Ok(()))
}

/// Forget used setup links that expired before `before`: the time check rejects them anyway.
pub async fn prune_setup_links(db: &Db, before: u64) -> R<u64> {
    Ok(sqlx::query("DELETE FROM used_setup_links WHERE exp < ?")
        .bind(before as i64)
        .execute(db)
        .await?
        .rows_affected())
}

/// A revocation of the manifest signer seen earlier: `(revoked_at, reason)`.
pub async fn signer_revocation(db: &Db, fingerprint: &str) -> R<Option<(u64, String)>> {
    let r: Option<(i64, String)> =
        sqlx::query_as("SELECT revoked_at, reason FROM signer_revocations WHERE fingerprint = ?")
            .bind(fingerprint)
            .fetch_optional(db)
            .await?;
    Ok(r.map(|(at, reason)| (at as u64, reason)))
}

pub async fn record_signer_revocation(
    db: &Db,
    fingerprint: &str,
    revoked_at: u64,
    reason: &str,
    now: u64,
) -> R<()> {
    sqlx::query(
        "INSERT INTO signer_revocations (fingerprint, revoked_at, reason, seen_at) VALUES (?, ?, ?, ?)
         ON CONFLICT(fingerprint) DO NOTHING",
    )
    .bind(fingerprint)
    .bind(revoked_at as i64)
    .bind(reason)
    .bind(now as i64)
    .execute(db)
    .await?;
    Ok(())
}

/// Forget a device's push token (the push service said it is no longer valid).
pub async fn clear_push(db: &Db, id: &str) -> R<()> {
    sqlx::query("UPDATE devices SET push = ? WHERE device_id = ?")
        .bind(serde_json::to_string(&PushTarget::None).expect("json"))
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn touch_device(db: &Db, id: &str, now: i64) -> R<()> {
    sqlx::query("UPDATE devices SET last_seen = ? WHERE device_id = ?")
        .bind(now)
        .bind(id)
        .execute(db)
        .await?;
    Ok(())
}

pub async fn list_devices(db: &Db) -> R<Vec<DeviceRecord>> {
    Ok(sqlx::query("SELECT * FROM devices ORDER BY device_id")
        .fetch_all(db)
        .await?
        .iter()
        .map(device_from_row)
        .collect())
}

pub async fn delete_device(db: &Db, id: &str) -> R<bool> {
    Ok(sqlx::query("DELETE FROM devices WHERE device_id = ?")
        .bind(id)
        .execute(db)
        .await?
        .rows_affected()
        > 0)
}

/// One audit row. Requests are logged in full (they carry only ciphertext, digests or
/// messages to sign); responses are logged as the device signed them (results are sealed).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AuditEvent {
    pub ts: i64,
    pub event: String,
    pub client_id: Option<String>,
    pub device_id: Option<String>,
    pub req_id: Option<String>,
    pub key_fingerprint: Option<String>,
    pub op: Option<String>,
    pub mechanism: Option<String>,
    pub host: Option<String>,
    pub purpose: Option<String>,
    pub consumer: Option<String>,
    pub input_sha256: Option<String>,
    pub status: Option<String>,
    pub reason: Option<String>,
    pub detail: Option<String>,
    #[serde(serialize_with = "b64_opt")]
    pub request: Option<Vec<u8>>,
    #[serde(serialize_with = "b64_opt")]
    pub response: Option<Vec<u8>>,
}

fn b64_opt<S: serde::Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    use base64::Engine as _;
    match v {
        Some(b) => s.serialize_some(&base64::engine::general_purpose::STANDARD.encode(b)),
        None => s.serialize_none(),
    }
}

pub async fn audit(db: &Db, e: &AuditEvent) -> R<()> {
    sqlx::query(
        "INSERT INTO audit (ts, event, client_id, device_id, req_id, key_fingerprint, op, mechanism, host, purpose,
           consumer, input_sha256, status, reason, detail, request, response)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(e.ts)
    .bind(&e.event)
    .bind(&e.client_id)
    .bind(&e.device_id)
    .bind(&e.req_id)
    .bind(&e.key_fingerprint)
    .bind(&e.op)
    .bind(&e.mechanism)
    .bind(&e.host)
    .bind(&e.purpose)
    .bind(&e.consumer)
    .bind(&e.input_sha256)
    .bind(&e.status)
    .bind(&e.reason)
    .bind(&e.detail)
    .bind(&e.request)
    .bind(&e.response)
    .execute(db)
    .await?;
    Ok(())
}

pub async fn audit_since(db: &Db, since: i64) -> R<Vec<AuditEvent>> {
    let rows = sqlx::query("SELECT * FROM audit WHERE ts >= ? ORDER BY id")
        .bind(since)
        .fetch_all(db)
        .await?;
    Ok(rows
        .iter()
        .map(|r| AuditEvent {
            ts: r.get("ts"),
            event: r.get("event"),
            client_id: r.get("client_id"),
            device_id: r.get("device_id"),
            req_id: r.get("req_id"),
            key_fingerprint: r.get("key_fingerprint"),
            op: r.get("op"),
            mechanism: r.get("mechanism"),
            host: r.get("host"),
            purpose: r.get("purpose"),
            consumer: r.get("consumer"),
            input_sha256: r.get("input_sha256"),
            status: r.get("status"),
            reason: r.get("reason"),
            detail: r.get("detail"),
            request: r.get("request"),
            response: r.get("response"),
        })
        .collect())
}
