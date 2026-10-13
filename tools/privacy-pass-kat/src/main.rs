//! JSON-lines reference bridge. Synthetic test keys only; no transport service.
use p384::NistP384;
use privacypass::{
    TokenType,
    auth::authenticate::TokenChallenge,
    common::private::{deserialize_public_key, serialize_public_key},
    private_tokens::{PrivateToken, TokenRequest, TokenResponse, server::Server},
    test_utils::{nonce_store::MemoryNonceStore, private_memory_store::MemoryKeyStoreVoprf},
};
use serde_json::{Value, json};
use std::io::{self, BufRead};
use tls_codec::{Deserialize, Serialize};
use voprf::Group;

type R<T> = Result<T, String>;
fn checked<T, E: std::fmt::Debug>(result: Result<T, E>) -> R<T> {
    result.map_err(|e| format!("{e:?}"))
}
fn bytes(v: &Value, key: &str) -> R<Vec<u8>> {
    checked(hex::decode(
        v[key].as_str().ok_or(format!("missing {key}"))?,
    ))
}
fn challenge(v: &Value) -> R<TokenChallenge> {
    let data = bytes(v, "challenge")?;
    let mut input = data.as_slice();
    let out = checked(TokenChallenge::tls_deserialize(&mut input))?;
    if !input.is_empty() {
        return Err("trailing challenge bytes".into());
    }
    Ok(out)
}
async fn execute(v: Value) -> R<Value> {
    let op = v["op"].as_str().ok_or("missing op")?;
    if op == "validate_request" {
        let raw = bytes(&v, "request")?;
        if raw.len() != 52 || raw[..2] != [0, 1] {
            return Err("request framing".into());
        }
        checked(deserialize_public_key::<NistP384>(&raw[3..]))?;
        return Ok(json!({"valid":true}));
    }
    if op == "challenge" {
        let token_type = match v["token_type"].as_u64() {
            Some(1) => TokenType::PrivateP384,
            Some(2) => TokenType::Public,
            _ => return Err("unsupported token type".into()),
        };
        let issuer = v["issuer_name"].as_str().ok_or("issuer name")?;
        if issuer.is_empty() || issuer.len() > 65535 {
            return Err("issuer name length".into());
        }
        let c = TokenChallenge::new(token_type, issuer, None, &[]);
        return Ok(
            json!({"challenge":hex::encode(checked(c.serialize())?),"digest":hex::encode(checked(c.digest())?)}),
        );
    }
    if op == "public_issue" {
        return public_issue(&v).await;
    }
    if op == "public_fixture" {
        return public_fixture(v["index"].as_u64().ok_or("index")? as usize).await;
    }
    let keys = MemoryKeyStoreVoprf::<NistP384>::default();
    let server = Server::<NistP384>::new();
    let public = if v.get("secret_key").is_some() {
        checked(server.set_key(&keys, &bytes(&v, "secret_key")?).await)?
    } else {
        checked(
            server
                .create_keypair_with_params(&keys, &bytes(&v, "seed")?, &bytes(&v, "info")?)
                .await,
        )?
    };
    let public_bytes = serialize_public_key::<NistP384>(public);
    if op == "derive" {
        return Ok(json!({"public_key":hex::encode(public_bytes)}));
    }
    if op == "verify" {
        let raw = bytes(&v, "token")?;
        let mut input = raw.as_slice();
        let token = checked(PrivateToken::<NistP384>::tls_deserialize(&mut input))?;
        if !input.is_empty() {
            return Err("trailing token bytes".into());
        }
        let info = json!({"nonce":hex::encode(token.nonce()),"key_id":hex::encode(token.token_key_id()),"challenge_digest":hex::encode(token.challenge_digest()),"public_key":hex::encode(public_bytes)});
        checked(
            server
                .redeem_token(&keys, &MemoryNonceStore::default(), token)
                .await,
        )?;
        return Ok(info);
    }
    if op != "private_issue" {
        return Err("unknown op".into());
    }
    let pinned = if v.get("pinned_public").is_some() {
        checked(deserialize_public_key::<NistP384>(&bytes(
            &v,
            "pinned_public",
        )?))?
    } else {
        public
    };
    let nonce = bytes(&v, "nonce")?.try_into().map_err(|_| "nonce length")?;
    let blind = checked(
        <<NistP384 as voprf::CipherSuite>::Group as Group>::deserialize_scalar(&bytes(
            &v, "blind",
        )?),
    )?;
    let (request, state) = checked(TokenRequest::<NistP384>::issue_token_request_with_params(
        pinned,
        &challenge(&v)?,
        nonce,
        blind,
    ))?;
    let request_bytes = checked(request.tls_serialize_detached())?;
    let response = if v.get("response").is_some() {
        let data = bytes(&v, "response")?;
        let mut input = data.as_slice();
        let response = checked(TokenResponse::<NistP384>::tls_deserialize(&mut input))?;
        if !input.is_empty() {
            return Err("trailing response bytes".into());
        }
        response
    } else {
        checked(server.issue_token_response(&keys, request).await)?
    };
    let token = checked(response.issue_token(&state))?;
    Ok(
        json!({"public_key":hex::encode(public_bytes),"request":hex::encode(request_bytes),
        "token":hex::encode(checked(token.tls_serialize_detached())?),"nonce":hex::encode(token.nonce()),
        "key_id":hex::encode(token.token_key_id()),"challenge_digest":hex::encode(token.challenge_digest())}),
    )
}
async fn public_fixture(index: usize) -> R<Value> {
    let fixture: Value = checked(serde_json::from_str(include_str!(
        "../../../reference/src/hum_reference/data/rfc9578.json"
    )))?;
    if !(5..10).contains(&index) {
        return Err("public RFC fixture index must be 5..9".into());
    }
    public_issue(&fixture["cases"][index]).await
}
async fn public_issue(c: &Value) -> R<Value> {
    use blind_rsa_signatures::{Deterministic, KeyPair, PSS, PublicKey, SecretKey, Sha384};
    use privacypass::{
        public_tokens::{TokenRequest, det_rng::DeterministicRng, server::IssuerServer},
        test_utils::public_memory_store::IssuerMemoryKeyStore,
    };
    let sk = checked(SecretKey::<Sha384, PSS, Deterministic>::from_pem(checked(
        std::str::from_utf8(&bytes(c, "skI")?),
    )?))?;
    let pk = checked(PublicKey::<Sha384, PSS, Deterministic>::from_spki(&bytes(
        c, "pkI",
    )?))?;
    let keys = IssuerMemoryKeyStore::default();
    let issuer = IssuerServer::new();
    checked(
        issuer
            .set_keypair(&keys, KeyPair { sk, pk: pk.clone() })
            .await,
    )?;
    let mut blind = bytes(c, "blind")?;
    blind.reverse();
    let mut rng = DeterministicRng::new(bytes(c, "nonce")?, bytes(c, "salt")?, blind);
    let ch = checked(TokenChallenge::deserialize(&bytes(c, "token_challenge")?))?;
    let (request, state) = checked(TokenRequest::new(&mut rng, pk, &ch))?;
    let req = checked(request.tls_serialize_detached())?;
    let response = checked(issuer.issue_token_response(&keys, request).await)?;
    let response_bytes = checked(response.tls_serialize_detached())?;
    let token = checked(response.issue_token(&state))?;
    Ok(
        json!({"request":hex::encode(req),"response":hex::encode(response_bytes),"token":hex::encode(checked(token.tls_serialize_detached())?)}),
    )
}
#[tokio::main(flavor = "current_thread")]
async fn main() {
    for line in io::stdin().lock().lines() {
        let result = match line {
            Ok(line) => match serde_json::from_str(&line) {
                Ok(v) => execute(v).await,
                Err(_) => Err("invalid JSON".into()),
            },
            Err(_) => Err("input error".into()),
        };
        println!(
            "{}",
            match result {
                Ok(out) => json!({"ok":out}),
                Err(error) => json!({"error":error}),
            }
        );
    }
}
