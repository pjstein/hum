//! Build/FFI feasibility only: library BLS checks, not Hum BBS implementation.
use blst::{BLST_ERROR, min_pk};

uniffi::setup_scaffolding!();

/// Results cross the generated UniFFI ABI as a record.
#[derive(Debug, uniffi::Record)]
pub struct ProbeResult {
    pub valid_signature: bool,
    pub altered_message_rejected: bool,
    pub malformed_public_key_rejected: bool,
    pub malformed_signature_rejected: bool,
    pub public_key_bytes: u32,
    pub signature_bytes: u32,
}

/// Uses only synthetic fixed test material; never takes a user's secret.
#[uniffi::export]
pub fn run_probe() -> ProbeResult {
    // All key generation, signing, group validation and pairings are blst operations.
    let secret = min_pk::SecretKey::key_gen(&[42; 32], &[]).expect("fixed valid test IKM");
    let public = secret.sk_to_pk();
    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let message = b"Hum Android blst feasibility probe";
    let signature = secret.sign(message, dst, &[]);
    let public = min_pk::PublicKey::key_validate(&public.to_bytes()).expect("valid subgroup");
    let signature = min_pk::Signature::sig_validate(&signature.to_bytes(), true)
        .expect("valid nonidentity subgroup");
    ProbeResult {
        valid_signature: signature.verify(true, message, dst, &[], &public, true)
            == BLST_ERROR::BLST_SUCCESS,
        altered_message_rejected: signature.verify(true, b"altered", dst, &[], &public, true)
            != BLST_ERROR::BLST_SUCCESS,
        malformed_public_key_rejected: min_pk::PublicKey::key_validate(&[0; 48]).is_err(),
        malformed_signature_rejected: min_pk::Signature::sig_validate(&[0; 96], true).is_err(),
        public_key_bytes: public.to_bytes().len() as u32,
        signature_bytes: signature.to_bytes().len() as u32,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn pairing_and_validation_probe() {
        let result = super::run_probe();
        assert!(result.valid_signature);
        assert!(result.altered_message_rejected);
        assert!(result.malformed_public_key_rejected);
        assert!(result.malformed_signature_rejected);
        assert_eq!((result.public_key_bytes, result.signature_bytes), (48, 96));
    }
}
