//! The fake ledger: an append-only, hash-chained list of releases that checks
//! each release against its deck and the floors before appending. Replaced
//! by the Go ledger on Tessera (W1 ledger) behind the same port.

use crate::phone::Phone;
use crate::ports::{Cid, Floors, Ledger, Manifest, Refusal, Release, TapeRef, fake_hex};

/// One ledger entry.
#[derive(Clone, Debug)]
pub struct Entry {
    /// Position.
    pub seq: u64,
    /// Deck the release reports on.
    pub deck: Cid,
    /// Hash of the previous entry.
    pub prev: String,
    /// Hash of this entry.
    pub hash: String,
    /// The release.
    pub release: Release,
}

/// The fake ledger.
pub struct FakeLedger {
    tape: TapeRef,
    floors: Floors,
    /// Entries in order.
    pub entries: Vec<Entry>,
    /// Adversarial hook (wave 2): when set, the ledger rewrites an entry.
    pub lying: bool,
}

impl FakeLedger {
    /// A ledger enforcing `floors`.
    pub fn new(tape: TapeRef, floors: Floors) -> Self {
        Self {
            tape,
            floors,
            entries: vec![],
            lying: false,
        }
    }

    fn entry_hash(seq: u64, deck: &Cid, prev: &str, release: &Release) -> String {
        let body = serde_json::to_string(release).expect("release serialises");
        fake_hex(format!("{seq}/{deck}/{prev}/{body}").as_bytes())
    }
}

impl Ledger for FakeLedger {
    fn append(
        &mut self,
        release: &Release,
        deck: &Manifest,
        context: &Manifest,
    ) -> Result<u64, Refusal> {
        self.tape
            .borrow_mut()
            .see("ledger", "append", &(release, deck, context));
        let plan = Phone::plan_of(deck)?;
        if release.deck != deck.cid() {
            return Err(Refusal("release does not pin this deck version".into()));
        }
        if release.rho > plan.rho + 1e-12 || release.delta > plan.delta {
            return Err(Refusal("release spent more than the deck planned".into()));
        }
        let context_floors: Floors = context
            .body
            .get("floors")
            .and_then(|f| serde_json::from_value(f.clone()).ok())
            .ok_or_else(|| Refusal("context has no floors".into()))?;
        let min_voters = context_floors.min_voters.max(self.floors.min_voters);
        if release.rho > self.floors.max_rho + 1e-12 || release.rho > context_floors.max_rho + 1e-12
        {
            return Err(Refusal("release spends more than the floors allow".into()));
        }
        // R6: a release with nothing unlocked has no `nHat` and no tables; one
        // that unlocked anything must be at or above the minimum.
        match release.n_hat {
            None if !release.parts.is_empty() || !release.tallies.is_empty() => {
                return Err(Refusal("tables published without a voter count".into()));
            }
            Some(n) if n < min_voters as f64 => {
                return Err(Refusal("release below the voter minimum".into()));
            }
            _ => {}
        }
        if self.entries.iter().any(|e| e.deck == release.deck) {
            return Err(Refusal("a release for this deck is already logged".into()));
        }
        if release.signers.len() < 2 {
            return Err(Refusal(
                "a release needs both aggregators' signatures".into(),
            ));
        }
        let seq = self.entries.len() as u64;
        let prev = self
            .entries
            .last()
            .map_or_else(|| "genesis".to_string(), |e| e.hash.clone());
        let hash = Self::entry_hash(seq, &release.deck, &prev, release);
        self.entries.push(Entry {
            seq,
            deck: release.deck.clone(),
            prev,
            hash,
            release: release.clone(),
        });
        if self.lying {
            // Wave 2 hook: a ledger that rewrites history. Detected by `verify`.
            if let Some(e) = self.entries.last_mut() {
                e.release.rho += 1.0;
            }
        }
        Ok(seq)
    }

    fn verify(&self) -> Result<u64, Refusal> {
        let mut prev = "genesis".to_string();
        for e in &self.entries {
            if e.prev != prev {
                return Err(Refusal(format!("entry {} does not chain", e.seq)));
            }
            let h = Self::entry_hash(e.seq, &e.deck, &e.prev, &e.release);
            if h != e.hash {
                return Err(Refusal(format!("entry {} was rewritten", e.seq)));
            }
            prev.clone_from(&e.hash);
        }
        Ok(self.entries.len() as u64)
    }
}
