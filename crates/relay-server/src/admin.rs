//! `relay-server admin`: list and revoke clients and devices, export the audit log. Works on
//! the SQLite file directly, so it can run while the relay is up (WAL) or down.

use crate::db::{self, Db};

fn out<T: serde::Serialize>(v: &T) {
    println!("{}", serde_json::to_string(v).expect("json"));
}

pub async fn list_clients(db: &Db) -> Result<(), String> {
    for c in db::list_clients(db).await.map_err(|e| e.to_string())? {
        out(&c);
    }
    Ok(())
}

pub async fn revoke_client(db: &Db, id: &str) -> Result<(), String> {
    if db::delete_client(db, id).await.map_err(|e| e.to_string())? {
        eprintln!("revoked client {id}; revoke it in every approver app too");
        Ok(())
    } else {
        Err(format!("no client {id}"))
    }
}

pub async fn list_devices(db: &Db) -> Result<(), String> {
    for d in db::list_devices(db).await.map_err(|e| e.to_string())? {
        out(&d);
    }
    Ok(())
}

pub async fn revoke_device(db: &Db, id: &str) -> Result<(), String> {
    if db::delete_device(db, id).await.map_err(|e| e.to_string())? {
        eprintln!("revoked device {id}; its attestation stays valid for clients until not_after");
        Ok(())
    } else {
        Err(format!("no device {id}"))
    }
}

/// One JSON object per line, oldest first.
pub async fn export_audit(db: &Db, since: i64) -> Result<(), String> {
    for e in db::audit_since(db, since)
        .await
        .map_err(|e| e.to_string())?
    {
        out(&e);
    }
    Ok(())
}
