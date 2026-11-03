use der::{Encode, Sequence, asn1::UintRef};
use passkeyd_abi::{config::Config, cryptography::CryptoBackend};

mod tpm;
mod r#virtual;

pub fn resolve_cryptography(confg: &Config) -> anyhow::Result<Box<dyn CryptoBackend>> {
    if confg.use_tpm_cryptography {
        // A failing TPM must fail this request, not abort the daemon: the
        // caller is in the middle of a ceremony and maps it to a CTAP error.
        Ok(Box::new(tpm::Tpm::new()?))
    } else {
        Ok(Box::new(r#virtual::Virtual))
    }
}

#[derive(Sequence)]
struct EcdsaSignature<'a> {
    pub r: UintRef<'a>,
    pub s: UintRef<'a>,
}
fn translate_es256_to_der(r_bytes: &[u8], s_bytes: &[u8]) -> Vec<u8> {
    let sig = EcdsaSignature {
        r: UintRef::new(r_bytes).expect("invalid r"),
        s: UintRef::new(s_bytes).expect("invalid s"),
    };
    sig.to_der().expect("DER-ASN.1 encoding failed")
}
