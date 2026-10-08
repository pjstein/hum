//! The fake credential scheme and issuer.
//!
//! The scheme stands in for the BBS-style credential of `verifier.md`. The
//! issuer signs a blinded request and never sees the card; a phone derives
//! its card from the signature and its own secret, and for each deck a
//! nullifier and a presentation. Verification uses the issuer's "public key",
//! which in this fake is the set of signatures it issued: that is enough to
//! refuse any presentation not backed by an issued card (a forged nullifier,
//! an agent) while no service ever sees a card or a nullifier beside
//! evidence. It gives no unforgeability or unlinkability beyond the
//! information flow; `hum-cred` (W1 identity) replaces it.

use std::cell::RefCell;
use std::collections::HashSet;
use std::rc::Rc;

use crate::ports::{Cid, Issuer, PresentationVerifier, Refusal, TapeRef, fake_hex};

/// Issuer key material shared between the issuer and every verifier of its
/// presentations (the "public key" of the fake).
#[derive(Debug, Default)]
pub struct SchemeState {
    issued: HashSet<String>,
}

/// Handle to the scheme state.
pub type Scheme = Rc<RefCell<SchemeState>>;

/// A fresh scheme.
pub fn new_scheme() -> Scheme {
    Rc::new(RefCell::new(SchemeState::default()))
}

/// What a phone computes from an issuer signature: its card.
pub fn card_from(issuer_signature: &str, blind_request: &str) -> String {
    format!(
        "rc_{}",
        fake_hex(format!("card/{issuer_signature}/{blind_request}").as_bytes())
    )
}

/// The per-deck nullifier of a card (`ballot.md`: scope `hum/ballot/1` ‖ the
/// deck lineage CID). Two decks of one context never share one.
pub fn nullifier_of(card: &str, deck: &Cid) -> String {
    format!(
        "vp_{}",
        fake_hex(format!("hum/ballot/1/{deck}/{card}").as_bytes())
    )
}

/// The presentation of a card for a deck and nullifier.
pub fn presentation_of(card: &str, deck: &Cid, nullifier: &str) -> String {
    format!(
        "zk_{}",
        fake_hex(format!("proof/{card}/{deck}/{nullifier}").as_bytes())
    )
}

/// Public verification: recompute from every issued card. O(cards) per
/// check, which is fine for a fake at simulator sizes.
pub struct SchemeVerifier(pub Scheme);

impl PresentationVerifier for SchemeVerifier {
    fn verify(&self, deck: &Cid, presentation: &str, nullifier: &str) -> bool {
        self.0.borrow().issued.iter().any(|card| {
            nullifier_of(card, deck) == nullifier
                && presentation_of(card, deck, nullifier) == presentation
        })
    }
}

/// The fake issuer.
pub struct FakeIssuer {
    tape: TapeRef,
    scheme: Scheme,
    /// How many cards it issued.
    pub issued: u64,
    /// Adversarial hook (wave 2): the verifier manifest asks for more
    /// evidence than it declares. The world refuses to request issuance.
    pub over_collects: bool,
}

impl FakeIssuer {
    /// New, over a scheme.
    pub fn new(tape: TapeRef, scheme: Scheme) -> Self {
        Self {
            tape,
            scheme,
            issued: 0,
            over_collects: false,
        }
    }
}

impl Issuer for FakeIssuer {
    fn issue(&mut self, blinded_request: &str) -> Result<String, Refusal> {
        self.tape
            .borrow_mut()
            .see("issuer", "issue", &blinded_request);
        if !blinded_request.starts_with("blind_") {
            return Err(Refusal("issuer only signs blinded requests".into()));
        }
        self.issued += 1;
        let sig = format!(
            "isig_{}",
            fake_hex(format!("sign/{blinded_request}").as_bytes())
        );
        // The issuer learns the card it is blind-signing in this fake only
        // through the scheme state, which models its public key, never through
        // anything it writes to the tape.
        self.scheme
            .borrow_mut()
            .issued
            .insert(card_from(&sig, blinded_request));
        Ok(sig)
    }
}
