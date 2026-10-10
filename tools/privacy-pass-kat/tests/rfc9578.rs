use p384::NistP384;
use privacypass::{
    auth::authenticate::TokenChallenge,
    common::{errors::RedeemTokenError, private::serialize_public_key},
    private_tokens::{TokenRequest, TokenResponse, server::Server},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use tls_codec::{Deserialize, Serialize};
use voprf::Group;

fn fixtures() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../../reference/src/hum_reference/data/rfc9578.json"
    ))
    .unwrap()
}
fn field(c: &serde_json::Value, name: &str) -> Vec<u8> {
    hex::decode(c[name].as_str().unwrap()).unwrap()
}

#[tokio::test]
async fn all_five_private_rfc_fixtures() {
    for c in fixtures()["cases"].as_array().unwrap().iter().take(5) {
        let keys = MemoryKeyStoreVoprf::<NistP384>::default();
        let spent = MemoryNonceStore::default();
        let server = Server::new();
        let public = server.set_key(&keys, &field(c, "skI")).await.unwrap();
        assert_eq!(serialize_public_key::<NistP384>(public), field(c, "pkI"));
        let challenge = TokenChallenge::deserialize(&field(c, "token_challenge")).unwrap();
        let blind = <<NistP384 as voprf::CipherSuite>::Group as Group>::deserialize_scalar(&field(
            c, "blind",
        ))
        .unwrap();
        let nonce = field(c, "nonce").try_into().unwrap();
        let (request, state) = TokenRequest::<NistP384>::issue_token_request_with_params(
            public, &challenge, nonce, blind,
        )
        .unwrap();
        assert_eq!(
            request.tls_serialize_detached().unwrap(),
            field(c, "token_request")
        );
        let fixture_response =
            TokenResponse::<NistP384>::tls_deserialize(&mut field(c, "token_response").as_slice())
                .unwrap();
        let token = fixture_response.issue_token(&state).unwrap();
        assert_eq!(token.tls_serialize_detached().unwrap(), field(c, "token"));
        let generated = server.issue_token_response(&keys, request).await.unwrap();
        assert_eq!(
            generated
                .issue_token(&state)
                .unwrap()
                .tls_serialize_detached()
                .unwrap(),
            field(c, "token")
        );
        assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());
        server
            .redeem_token(&keys, &spent, token.clone())
            .await
            .unwrap();
        assert_eq!(
            server.redeem_token(&keys, &spent, token).await,
            Err(RedeemTokenError::DoubleSpending)
        );
        let mut corrupt = field(c, "token_response");
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        let response = TokenResponse::<NistP384>::tls_deserialize(&mut corrupt.as_slice()).unwrap();
        assert!(response.issue_token(&state).is_err());
    }
}

#[tokio::test]
async fn all_five_public_rfc_fixtures() {
    use blind_rsa_signatures::{Deterministic, KeyPair, PSS, PublicKey, SecretKey, Sha384};
    use privacypass::{
        public_tokens::{
            TokenRequest, det_rng::DeterministicRng, public_key_to_truncated_token_key_id,
            server::*,
        },
        test_utils::public_memory_store::{IssuerMemoryKeyStore, OriginMemoryKeyStore},
    };
    for c in fixtures()["cases"].as_array().unwrap().iter().skip(5) {
        let issuer_keys = IssuerMemoryKeyStore::default();
        let origin_keys = OriginMemoryKeyStore::default();
        let spent = MemoryNonceStore::default();
        let issuer = IssuerServer::new();
        let origin = OriginServer::new();
        let sk = SecretKey::<Sha384, PSS, Deterministic>::from_pem(
            std::str::from_utf8(&field(c, "skI")).unwrap(),
        )
        .unwrap();
        let pk = PublicKey::<Sha384, PSS, Deterministic>::from_spki(&field(c, "pkI")).unwrap();
        assert_eq!(sk.public_key().unwrap().to_spki().unwrap(), field(c, "pkI"));
        issuer
            .set_keypair(&issuer_keys, KeyPair { sk, pk: pk.clone() })
            .await
            .unwrap();
        origin_keys
            .insert(
                public_key_to_truncated_token_key_id(&pk).unwrap(),
                pk.clone(),
            )
            .await;
        let mut blind = field(c, "blind");
        blind.reverse();
        let mut rng = DeterministicRng::new(field(c, "nonce"), field(c, "salt"), blind);
        let challenge = TokenChallenge::deserialize(&field(c, "token_challenge")).unwrap();
        let (request, state) = TokenRequest::new(&mut rng, pk, &challenge).unwrap();
        assert_eq!(
            request.tls_serialize_detached().unwrap(),
            field(c, "token_request")
        );
        let response = issuer
            .issue_token_response(&issuer_keys, request)
            .await
            .unwrap();
        assert_eq!(
            response.tls_serialize_detached().unwrap(),
            field(c, "token_response")
        );
        let token = response.issue_token(&state).unwrap();
        assert_eq!(token.tls_serialize_detached().unwrap(), field(c, "token"));
        assert_eq!(token.challenge_digest(), &challenge.digest().unwrap());
        origin
            .redeem_token(&origin_keys, &spent, token.clone())
            .await
            .unwrap();
        assert_eq!(
            origin.redeem_token(&origin_keys, &spent, token).await,
            Err(RedeemTokenError::DoubleSpending)
        );
    }
}
