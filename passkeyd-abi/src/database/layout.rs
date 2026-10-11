use std::time::Duration;

use bytes::Bytes;
use ctap_types::{
    serde::cbor_deserialize,
    webauthn::{PublicKeyCredentialRpEntity, PublicKeyCredentialUserEntity},
};

use rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::{
    cryptography::CryptoPair,
    database::{get_passkey, increment_sign_count, set_passkey},
    utils::CborVec,
};

#[derive(Serialize, Deserialize)]
pub enum CredentialType {
    PublicKey,
}

#[derive(Serialize, Deserialize)]
pub struct OtherUI {
    pub user: PublicKeyCredentialUserEntity,
    pub site_icon: Option<bytes::Bytes>,
    pub user_icon: Option<bytes::Bytes>,
}

#[derive(Serialize, Deserialize)]
pub struct CredentialSource {
    // According to spec,
    // If requireResidentKey is true or the authenticator chooses to create a client-side discoverable public key credential source:
    // Let credentialId be a new credential id.
    // Set credentialSource.id to credentialId.
    pub id: [u8; 32], //but unlike spec, it wil always be a cerdential ID
    // r#type: "public-key",
    pub crypto_pair: CryptoPair,
    pub rp_id: ctap_types::String<256>,
    pub user_handle: ctap_types::Bytes<64>, //userEntity.id
    pub other_ui: OtherUI,
}

#[derive(Serialize, Deserialize)]
pub struct Passkey {
    pub sign_count: u32,
    // pub credential_id: [u8; 32],
    pub credential_type: CredentialType,
    pub credential_source: CredentialSource,
    /// Which user owns this passkey.
    ///
    /// `LEGACY_UID` marks a passkey written before passkeys were owned by a
    /// user. It never matches the active uid, so such a passkey is invisible
    /// until `passkeyd-migrate` assigns it to the old `GUI_UID` owner.
    ///
    /// `serde(default)` is what makes those old files readable at all; without
    /// it, deserializing them fails outright.
    #[serde(default)]
    pub uid: u32,
}

/// The uid on passkeys written before ownership existed.
///
/// Zero is root, and `GUI_UID` existed precisely to keep the GUI off root, so
/// no real passkey can carry it.
pub const LEGACY_UID: u32 = 0;

#[derive(Serialize, Deserialize)]
pub struct StoreablePasskey(Vec<u8>); //why store in cbor instead of sotring directly? well idk, why not do it ? free will??

impl Passkey {
    pub fn new(
        rp_id: ctap_types::String<256>,
        user: PublicKeyCredentialUserEntity,
        crypto_pair: CryptoPair,
        uid: u32,
    ) -> Self {
        let mut credential_id = [0u8; 32];
        rand::rng().fill_bytes(&mut credential_id);

        let mut other_ui = OtherUI {
            site_icon: None,
            user,
            user_icon: None,
        };

        if let Some(user_icon_url) = &other_ui.user.icon {
            let result = ureq::get(user_icon_url.as_str())
                .config()
                .timeout_global(Some(Duration::from_secs(5)))
                .build()
                .call()
                .ok();
            other_ui.user_icon = result
                .and_then(|mut x| x.body_mut().read_to_vec().ok())
                .map(Bytes::from_owner);
        };

        other_ui.site_icon = None;
        // if let Some(site_icon_url) = &other_ui.user.icon {
        //     let result = ureq::get(site_icon_url.as_str())
        //         .config()
        //         .timeout_global(Some(Duration::from_secs(5)))
        //         .build()
        //         .call()
        //         .ok();
        //     other_ui.site_icon = result
        //         .and_then(|mut x| x.body_mut().read_to_vec().ok())
        //         .map(|x| Bytes::from_owner(x));
        // };

        let source = CredentialSource {
            id: credential_id,
            user_handle: other_ui.user.id.clone(),
            other_ui,
            rp_id,
            crypto_pair,
        };

        Self {
            sign_count: 0,
            credential_type: CredentialType::PublicKey,
            credential_source: source,
            uid,
        }
    }

    pub fn store(self, rp: PublicKeyCredentialRpEntity) {
        set_passkey(rp, self);
    }

    pub fn sign_increment(self, rp: PublicKeyCredentialRpEntity) {
        increment_sign_count(rp, self);
    }

    pub fn get(
        rp: &PublicKeyCredentialRpEntity,
        credential_id: &[u8],
        uid: u32,
    ) -> Option<(PublicKeyCredentialRpEntity, Self)> {
        get_passkey(rp, credential_id, uid)
    }
}

impl TryInto<Passkey> for StoreablePasskey {
    type Error = ctap_types::serde::Error;
    fn try_into(self) -> Result<Passkey, Self::Error> {
        cbor_deserialize(&self.0)
    }
}

impl From<Passkey> for StoreablePasskey {
    fn from(value: Passkey) -> Self {
        Self(CborVec::from_serializable(value, size_of::<Passkey>()).into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cryptography::VirtualKeyPair;

    /// A passkey as it was stored before ownership existed: the CBOR map has
    /// no `uid` key at all.
    #[derive(Serialize)]
    struct OwnerlessPasskey {
        sign_count: u32,
        credential_type: CredentialType,
        credential_source: CredentialSource,
    }

    fn sample() -> Passkey {
        Passkey::new(
            ctap_types::String::try_from("example.com").unwrap(),
            PublicKeyCredentialUserEntity {
                id: ctap_types::Bytes::from_slice(&[1u8; 16]).unwrap(),
                icon: None,
                name: Some("someone".into()),
                display_name: None,
            },
            {
                let signing_key = p256::ecdsa::SigningKey::random(&mut p256::elliptic_curve::rand_core::OsRng);
                let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
                CryptoPair::Virtual(Box::new(VirtualKeyPair::Es256(signing_key, verifying_key)))
            },
            1000,
        )
    }

    #[test]
    fn uid_survives_a_round_trip() {
        let passkey = sample();
        let stored: StoreablePasskey = passkey.into();
        let restored: Passkey = stored.try_into().expect("round trip failed");
        assert_eq!(restored.uid, 1000);
    }

    /// The upgrade path: files written before `uid` existed must still load,
    /// landing on the legacy marker so they stay invisible until migrated.
    #[test]
    fn a_passkey_without_a_uid_is_legacy() {
        let passkey = sample();
        let ownerless = OwnerlessPasskey {
            sign_count: passkey.sign_count,
            credential_type: CredentialType::PublicKey,
            credential_source: passkey.credential_source,
        };

        let bytes = CborVec::from_serializable(ownerless, 1024).into_inner();
        let restored: Passkey =
            cbor_deserialize(&bytes).expect("an ownerless passkey must still deserialize");

        assert_eq!(restored.uid, LEGACY_UID);
    }

    #[test]
    fn the_legacy_marker_is_not_a_real_user() {
        // Zero is root, which the old GUI_UID setting existed to avoid.
        assert_eq!(LEGACY_UID, 0);
    }
}
