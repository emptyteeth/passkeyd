use anyhow::Context;
use ctap_types::{serde::cbor_deserialize, webauthn::PublicKeyCredentialRpEntity};
use sha2::Digest;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};
pub mod layout;
use layout::{Passkey, StoreablePasskey};
use log::{error, info};

use crate::utils::CborVec;

#[cfg(debug_assertions)]
const FSBASE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/TEMPP_DATABASE");

#[cfg(not(debug_assertions))]
const FSBASE: &str = "/var/lib/passkeyd/database";

pub fn database_dir() -> PathBuf {
    PathBuf::from(FSBASE)
}

// A metadata is a PublicKeyCredentialRpEntity
// and suffixed with "table" is a PathBuf

/// Writes `bytes` to `path` through a temporary file and a rename.
///
/// A plain `fs::write` interrupted halfway leaves a truncated file behind, and
/// every later read of that passkey fails — which matters most for the TPM
/// blobs, whose only other copy is inside the passkey itself. Renaming is
/// atomic, so readers see either the old file or the new one.
///
/// The temporary name carries the pid because `passkeyd-manager` writes to the
/// same store from another process.
fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let temporary = path.with_extension(format!("tmp-{}", std::process::id()));

    let mut file = fs::File::create(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&temporary, path)?;

    // Best effort: fsync the directory so the rename itself survives a crash.
    // Not every filesystem allows this, and the data is already safe.
    if let Some(directory) = path.parent()
        && let Ok(directory) = fs::File::open(directory)
    {
        let _ = directory.sync_all();
    }

    Ok(())
}

fn update_metadata(rp: &PublicKeyCredentialRpEntity, rp_path: &Path) -> std::io::Result<()> {
    let metadata_path = rp_path.join("metadata");
    let meta = CborVec::from_serializable(rp, size_of::<PublicKeyCredentialRpEntity>());
    write_atomic(&metadata_path, meta.as_ref())
}

/// Reads a site's metadata, or `None` if it is missing or unreadable.
///
/// A single damaged file must not take the daemon down: the caller treats the
/// site as unusable and everything else keeps working.
fn get_metadata(rp_path: &Path) -> Option<PublicKeyCredentialRpEntity> {
    let metadata_path = rp_path.join("metadata");
    let cbor_buff = match fs::read(&metadata_path) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Cannot read {}: {e}", metadata_path.display());
            return None;
        }
    };

    match cbor_deserialize(&cbor_buff) {
        Ok(metadata) => Some(metadata),
        Err(e) => {
            error!("Cannot decode {}: {e:?}", metadata_path.display());
            None
        }
    }
}

fn get_rp_table(rp: &PublicKeyCredentialRpEntity, create: bool) -> Option<PathBuf> {
    let rp_hash = sha2::Sha256::digest(rp.id.as_bytes());
    let rp_hex_hash = hex::encode(rp_hash);
    let rp_table = database_dir().join(rp_hex_hash);
    if rp_table.exists() {
        Some(rp_table)
    } else if create {
        if let Err(e) = fs::create_dir(&rp_table) {
            error!("Cannot create {}: {e}", rp_table.display());
            return None;
        }
        if let Err(e) = update_metadata(rp, &rp_table) {
            error!("Cannot write {}: {e}", rp_table.join("metadata").display());
            return None;
        }
        Some(rp_table)
    } else {
        None
    }
}

fn get_table(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
    create: bool,
) -> Option<PathBuf> {
    let rp_table = get_rp_table(rp, create)?;
    let user_table = rp_table.join(cerdential_id_to_str(credential_id));

    // Writing creates the file atomically, so there is nothing to create here.
    (create || user_table.exists()).then_some(user_table)
}

pub fn get_passkey(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
    uid: u32,
) -> Option<(PublicKeyCredentialRpEntity, Passkey)> {
    let table = get_table(rp, credential_id, false)?;

    // A damaged file is treated as "no such passkey" rather than a panic: the
    // request fails cleanly and the rest of the store stays usable.
    let cbor_data = match fs::read(&table) {
        Ok(bytes) => bytes,
        Err(e) => {
            error!("Cannot read {}: {e}", table.display());
            return None;
        }
    };

    let data: StoreablePasskey = match cbor_deserialize(&cbor_data) {
        Ok(data) => data,
        Err(e) => {
            error!("Cannot decode {}: {e:?}", table.display());
            return None;
        }
    };

    let metadata = get_metadata(table.parent()?)?;

    let passkey: Passkey = match data.try_into() {
        Ok(passkey) => passkey,
        Err(e) => {
            error!("Cannot unpack the passkey in {}: {e:?}", table.display());
            return None;
        }
    };

    // Ownership is checked here as well as in `get_passkeys`. A caller can
    // reach this path through a request's allow list, naming a credential
    // id directly, so filtering only the listing would let one user use
    // another's passkey.
    if passkey.uid != uid {
        return None;
    }

    Some((metadata, passkey))
}

pub fn remove_passkey(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
) -> std::io::Result<()> {
    match get_table(rp, credential_id, false) {
        Some(table) => fs::remove_file(table),
        None => Ok(()),
    }
}

pub fn remove_table(rp: &PublicKeyCredentialRpEntity) -> std::io::Result<()> {
    match get_rp_table(rp, false) {
        Some(table) => fs::remove_dir_all(table),
        None => Ok(()),
    }
}

pub fn get_passkeys(
    rp: &PublicKeyCredentialRpEntity,
    uid: u32,
) -> Option<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    let table = get_rp_table(rp, false)?;
    let metadata = get_metadata(&table)?;

    let dir_entries = match fs::read_dir(&table) {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot list {}: {e}", table.display());
            return None;
        }
    };

    let mut passkeys: Vec<Passkey> = Vec::new();

    for entry in dir_entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                error!("Cannot read an entry in {}: {e}", table.display());
                continue;
            }
        };
        if path.ends_with("metadata") {
            continue;
        }

        // One damaged file must not hide every other passkey for this site.
        let cbor_data = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Cannot read {}: {e}", path.display());
                continue;
            }
        };
        let data: StoreablePasskey = match cbor_deserialize(&cbor_data) {
            Ok(data) => data,
            Err(e) => {
                error!("Cannot decode {}: {e:?}", path.display());
                continue;
            }
        };
        let passkey: Passkey = match data.try_into() {
            Ok(passkey) => passkey,
            Err(e) => {
                error!("Cannot unpack the passkey in {}: {e:?}", path.display());
                continue;
            }
        };

        // The store is shared; only the owner's passkeys are returned.
        if passkey.uid == uid {
            passkeys.push(passkey);
        }
    }

    Some((metadata, passkeys))
}

/// Every passkey, whoever owns it. Only for `passkeyd-manager`, which runs as
/// root and shows the whole store with each entry's owner.
pub fn get_all_passkeys(
    rp: &PublicKeyCredentialRpEntity,
) -> Option<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    let table = get_rp_table(rp, false)?;
    let metadata = get_metadata(&table)?;

    let dir_entries = match fs::read_dir(&table) {
        Ok(entries) => entries,
        Err(e) => {
            error!("Cannot list {}: {e}", table.display());
            return None;
        }
    };

    let mut passkeys = Vec::new();

    for entry in dir_entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                error!("Cannot read an entry in {}: {e}", table.display());
                continue;
            }
        };
        if path.ends_with("metadata") {
            continue;
        }

        let cbor_data = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Cannot read {}: {e}", path.display());
                continue;
            }
        };
        let data: StoreablePasskey = match cbor_deserialize(&cbor_data) {
            Ok(data) => data,
            Err(e) => {
                error!("Cannot decode {}: {e:?}", path.display());
                continue;
            }
        };
        match data.try_into() {
            Ok(passkey) => passkeys.push(passkey),
            Err(e) => error!("Cannot unpack the passkey in {}: {e:?}", path.display()),
        }
    }

    Some((metadata, passkeys))
}

pub fn set_passkey(rp: PublicKeyCredentialRpEntity, passkey: Passkey) -> anyhow::Result<()> {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true)
        .context("cannot open the passkey store")?;
    let storeable: StoreablePasskey = passkey.into();
    let bytes = CborVec::from_serializable(storeable, size_of::<Passkey>());

    write_atomic(&table, bytes.as_ref())
        .with_context(|| format!("cannot write {}", table.display()))?;

    info!("Passkey has been stored");
    Ok(())
}

pub fn increment_sign_count(
    rp: PublicKeyCredentialRpEntity,
    mut passkey: Passkey,
) -> anyhow::Result<()> {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true)
        .context("cannot open the passkey store")?;
    passkey.sign_count += 1;
    let storeable: StoreablePasskey = passkey.into();
    let bytes = CborVec::from_serializable(storeable, size_of::<Passkey>());

    write_atomic(&table, bytes.as_ref())
        .with_context(|| format!("cannot rewrite {}", table.display()))?;

    info!("Sign count has been updated");
    Ok(())
}

/// Every relying party that has passkeys stored.
///
/// The manager needs this: deletions arrive by `rp_id`, and the flat store is
/// keyed by a hash of it, so there is nothing to enumerate otherwise.
pub fn all_relying_parties() -> Vec<PublicKeyCredentialRpEntity> {
    let Ok(entries) = fs::read_dir(database_dir()) else {
        return Vec::new();
    };

    entries
        .flatten()
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| {
            let metadata = entry.path().join("metadata");
            let bytes = fs::read(metadata).ok()?;
            cbor_deserialize(&bytes).ok()
        })
        .collect()
}

/// The relying party with this id, if it has passkeys stored.
pub fn relying_party(rp_id: &str) -> Option<PublicKeyCredentialRpEntity> {
    let hash = sha2::Sha256::digest(rp_id.as_bytes());
    let path = database_dir().join(hex::encode(hash)).join("metadata");
    let bytes = fs::read(path).ok()?;
    cbor_deserialize(&bytes).ok()
}

fn cerdential_id_to_str(id: &[u8]) -> String {
    hex::encode(id)
}

/// Give every ownerless passkey to `uid`, returning how many were claimed.
///
/// Passkeys written before ownership existed carry [`layout::LEGACY_UID`] and
/// are invisible to every user until this runs. Called by `passkeyd-migrate`
/// with the old `GUI_UID`.
pub fn assign_legacy_uid(uid: u32) -> usize {
    let Ok(entries) = fs::read_dir(database_dir()) else {
        return 0;
    };

    let mut claimed = 0;

    for entry in entries.flatten() {
        let rp_path = entry.path();
        if !rp_path.is_dir() {
            continue;
        }

        let metadata_path = rp_path.join("metadata");
        if !metadata_path.exists() {
            continue;
        }

        let rp: PublicKeyCredentialRpEntity = match fs::read(&metadata_path)
            .ok()
            .and_then(|bytes| cbor_deserialize(&bytes).ok())
        {
            Some(rp) => rp,
            None => continue,
        };

        let Some((_, passkeys)) = get_all_passkeys(&rp) else {
            continue;
        };

        for mut passkey in passkeys {
            if passkey.uid != layout::LEGACY_UID {
                continue;
            }
            passkey.uid = uid;
            // Round-trips through the same path a normal write takes, so the
            // re-encryption of a TPM-backed key is handled for us.
            match set_passkey(rp.clone(), passkey) {
                Ok(()) => claimed += 1,
                Err(e) => error!("Cannot rewrite a passkey for {}: {e}", rp.id),
            }
        }
    }

    claimed
}
