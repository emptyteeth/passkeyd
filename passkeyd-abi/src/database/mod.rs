use ctap_types::{serde::cbor_deserialize, webauthn::PublicKeyCredentialRpEntity};
use sha2::Digest;
use std::{
    fs,
    path::{Path, PathBuf},
};
pub mod layout;
use layout::{Passkey, StoreablePasskey};
use log::info;

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

fn update_metadata(rp: &PublicKeyCredentialRpEntity, rp_path: &Path) {
    let metadata_path = rp_path.join("metadata");
    let meta = CborVec::from_serializable(rp, size_of::<PublicKeyCredentialRpEntity>());
    fs::write(metadata_path, meta).expect("failed to update metadata");
}

fn get_metadata(rp_path: &Path) -> PublicKeyCredentialRpEntity {
    let metadata_path = rp_path.join("metadata"); // path will always exist
    let cbor_buff = fs::read(metadata_path).expect("failed to update metadata");
    cbor_deserialize(&cbor_buff).expect("Failed to encode into cbor")
}

fn get_rp_table(rp: &PublicKeyCredentialRpEntity, create: bool) -> Option<PathBuf> {
    let rp_hash = sha2::Sha256::digest(rp.id.as_bytes());
    let rp_hex_hash = hex::encode(rp_hash);
    let rp_table = database_dir().join(rp_hex_hash);
    if rp_table.exists() {
        Some(rp_table)
    } else if create {
        fs::create_dir(&rp_table).expect("Failed to create dir, are you root?");
        update_metadata(rp, &rp_table);
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
    match get_rp_table(rp, create) {
        Some(rp_table) => {
            let user_table = rp_table.join(cerdential_id_to_str(credential_id));
            if user_table.exists() {
                Some(user_table)
            } else if create {
                fs::File::create(&user_table)
                    .expect("Failed to create file, do you have permission?");
                Some(user_table)
            } else {
                None
            }
        }
        None => None,
    }
}

pub fn get_passkey(
    rp: &PublicKeyCredentialRpEntity,
    credential_id: &[u8],
    uid: u32,
) -> Option<(PublicKeyCredentialRpEntity, Passkey)> {
    let table = get_table(rp, credential_id, false);
    if let Some(mut table) = table {
        let cbor_data = fs::read(&table).unwrap();
        let data: StoreablePasskey =
            cbor_deserialize(&cbor_data).expect("Failed to translate to cbor");
        let metadata = get_metadata({
            table.pop();
            &table
        });
        let passkey: Passkey = data.try_into().expect("decryption failed, are you root?");

        // Ownership is checked here as well as in `get_passkeys`. A caller can
        // reach this path through a request's allow list, naming a credential
        // id directly, so filtering only the listing would let one user use
        // another's passkey.
        if passkey.uid != uid {
            return None;
        }

        Some((metadata, passkey))
    } else {
        None
    }
}

pub fn remove_passkey(rp: &PublicKeyCredentialRpEntity, credential_id: &[u8]) {
    // duct taped function
    let table = get_table(rp, credential_id, false);
    if let Some(table) = table {
        fs::remove_file(&table).unwrap()
    }
}

pub fn remove_table(rp: &PublicKeyCredentialRpEntity) {
    // duct taped function
    let table = get_rp_table(rp, false);
    if let Some(table) = table {
        fs::remove_dir_all(&table).unwrap()
    }
}

pub fn get_passkeys(
    rp: &PublicKeyCredentialRpEntity,
    uid: u32,
) -> Option<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    let table = get_rp_table(rp, false);
    if let Some(table) = table {
        // let cbor_data = fs::read(table).unwrap();
        // cbor_deserialize(&cbor_data).expect("Failed to translate to cbor")
        let metadata = get_metadata(&table);
        let dir_entires = fs::read_dir(table)
            .expect("Failed to read dir, Do you have a permission?")
            .collect::<Vec<_>>();
        let mut passkeys: Vec<Passkey> = Vec::with_capacity(dir_entires.len());
        for entry in dir_entires {
            let table = entry
                .expect("Failed to read dir entry, do you have a permission?")
                .path();
            if table.ends_with("metadata") {
                continue;
            }
            let cbor_data = fs::read(table).unwrap();
            let data: StoreablePasskey =
                cbor_deserialize(&cbor_data).expect("Failed to translate to cbor");
            let passkey: Passkey = data.try_into().expect("decryption failed, are you root?");

            // The store is shared; only the owner's passkeys are returned.
            if passkey.uid == uid {
                passkeys.push(passkey);
            }
        }
        Some((metadata, passkeys))
    } else {
        None
        // return Vec::new();
    }
}

/// Every passkey, whoever owns it. Only for `passkeyd-manager`, which runs as
/// root and shows the whole store with each entry's owner.
pub fn get_all_passkeys(
    rp: &PublicKeyCredentialRpEntity,
) -> Option<(PublicKeyCredentialRpEntity, Vec<Passkey>)> {
    let table = get_rp_table(rp, false)?;
    let metadata = get_metadata(&table);
    let mut passkeys = Vec::new();

    for entry in fs::read_dir(table).expect("Failed to read dir, Do you have a permission?") {
        let path = entry
            .expect("Failed to read dir entry, do you have a permission?")
            .path();
        if path.ends_with("metadata") {
            continue;
        }
        let cbor_data = fs::read(path).unwrap();
        let data: StoreablePasskey =
            cbor_deserialize(&cbor_data).expect("Failed to translate to cbor");
        passkeys.push(data.try_into().expect("decryption failed, are you root?"));
    }

    Some((metadata, passkeys))
}

pub fn set_passkey(rp: PublicKeyCredentialRpEntity, passkey: Passkey) {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true).unwrap();
    let storeable: StoreablePasskey = passkey.into();
    // cbor_serialize_to(&storeable, &mut cbor_data).expect("Failed to translate to cbor");
    fs::write(
        table,
        CborVec::from_serializable(storeable, size_of::<Passkey>()),
    )
    .expect("Failed to cbor data into file");

    info!("Passkey has been stored");
}

pub fn increment_sign_count(rp: PublicKeyCredentialRpEntity, mut passkey: Passkey) {
    let table = get_table(&rp, passkey.credential_source.id.as_slice(), true).unwrap();
    passkey.sign_count += 1;
    let storeable: StoreablePasskey = passkey.into();
    fs::write(
        table,
        CborVec::from_serializable(storeable, size_of::<Passkey>()),
    )
    .expect("Failed to cbor data into file");

    info!("Sign count has been updated");
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
            set_passkey(rp.clone(), passkey);
            claimed += 1;
        }
    }

    claimed
}
