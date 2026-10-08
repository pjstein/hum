//! The fake aggregator: verifies each ballot's presentation with the issuer's
//! public key material, keeps one ballot per nullifier per deck, and on close
//! runs the research pipeline port once to produce the deck's release. Phones
//! apply the contribution cap (first K cards cast); the aggregator checks the
//! ballot's vote count against it and never drops votes itself. It
//! enforces what an honest aggregator enforces: the plan within the floors
//! (AG-3), one counted ballot per nullifier (AG-2), tiers decided from the
//! noised count and a release published only once per deck (AG-4). A close
//! below the minimum still produces a final release with nothing unlocked, so
//! the spend reaches the ledger (`release.md` R6).
//!
//! Replaced by `hum-release` behind the aggregator service in wave 1.

use std::collections::{BTreeMap, HashMap, HashSet};

use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::data::VoteMatrix;
use crate::phone::Phone;
use crate::pipeline::accounting::{DELTA, rho_to_eps};
use crate::pipeline::dp::{DpParams, dp_pipeline};
use crate::pipeline::{Analysis, Tallies};
use crate::ports::{
    Aggregator, Axes, Ballot, Cid, Floors, Manifest, PresentationVerifier, Receipt, Refusal,
    Release, ReleasePlan, TapeRef, fake_hex,
};

/// Protocol gates (`context.md`, "Protocol constants").
pub const GATE_COMMON: f64 = 300.0;
/// Noised voters for the map and groups tier.
pub const GATE_MAP: f64 = 800.0;

/// Which parts a release computes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tiering {
    /// Every part at every size, as the research experiments did. Not a
    /// conforming release; used by the Polis replay so its metrics are
    /// comparable with the research results.
    Research,
    /// The design's size gates, decided from the noised count: tallies at
    /// `minVoters`, common ground at `GATE_COMMON`, map and groups at `GATE_MAP`.
    Gated,
}

struct OpenDeck {
    plan: ReleasePlan,
    context_floors: Floors,
    ballots: BTreeMap<String, Ballot>,
}

/// The fake aggregator.
pub struct FakeAggregator {
    tape: TapeRef,
    floors: Floors,
    params: DpParams,
    tiering: Tiering,
    verifier: Box<dyn PresentationVerifier>,
    decks: HashMap<Cid, OpenDeck>,
    released: HashSet<Cid>,
    /// Phone-side facts from the last close, for the simulator's oracle only.
    /// Not part of the port: a real aggregator never has them.
    pub last_analysis: Option<Analysis>,
    /// Nullifiers whose ballots were counted in the last close, in matrix row order.
    pub last_rows: Vec<String>,
}

impl FakeAggregator {
    /// A fake aggregator enforcing `floors`, verifying presentations with `verifier`.
    pub fn new(
        tape: TapeRef,
        floors: Floors,
        tiering: Tiering,
        verifier: Box<dyn PresentationVerifier>,
    ) -> Self {
        Self {
            tape,
            floors,
            params: DpParams::default(),
            tiering,
            verifier,
            decks: HashMap::new(),
            released: HashSet::new(),
            last_analysis: None,
            last_rows: vec![],
        }
    }

    /// Override pipeline parameters (contribution cap and friends).
    #[must_use]
    pub fn with_params(mut self, params: DpParams) -> Self {
        self.params = params;
        self
    }

    /// Ballots held for a deck.
    pub fn ballots(&self, deck: &Cid) -> usize {
        self.decks.get(deck).map_or(0, |d| d.ballots.len())
    }

    fn matrix(deck: &OpenDeck) -> (VoteMatrix, Vec<String>) {
        let c = deck.plan.statements as usize;
        let mut m = VoteMatrix::new("ballots", deck.ballots.len(), c);
        let mut rows = Vec::with_capacity(deck.ballots.len());
        for (i, (pseudonym, b)) in deck.ballots.iter().enumerate() {
            for j in 0..c {
                m.set(i, j, b.votes.get(j).copied().flatten());
            }
            rows.push(pseudonym.clone());
        }
        (m, rows)
    }
}

impl Aggregator for FakeAggregator {
    fn open(&mut self, deck: &Manifest, context: &Manifest) -> Result<(), Refusal> {
        self.tape
            .borrow_mut()
            .see("aggregator", "open", &(deck, context));
        let plan = Phone::plan_of(deck)?;
        let context_floors: Floors = context
            .body
            .get("floors")
            .and_then(|f| serde_json::from_value(f.clone()).ok())
            .ok_or_else(|| Refusal("context has no floors".into()))?;
        if !self.floors.allows(&context_floors) {
            return Err(Refusal("context floors looser than protocol floors".into()));
        }
        if plan.rho > context_floors.max_rho + 1e-12
            || plan.delta > context_floors.max_delta
            || plan.cap == 0
        {
            return Err(Refusal("release plan breaks the context floors".into()));
        }
        if deck.refs.get("context").is_none_or(|c| *c != context.cid()) {
            return Err(Refusal("deck does not pin this context version".into()));
        }
        let cid = deck.cid();
        if self.released.contains(&cid) {
            return Err(Refusal("deck already released".into()));
        }
        self.decks.insert(
            cid,
            OpenDeck {
                plan,
                context_floors,
                ballots: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn submit(&mut self, ballot: &Ballot) -> Result<Receipt, Refusal> {
        self.tape.borrow_mut().see("aggregator", "submit", ballot);
        let deck = self
            .decks
            .get_mut(&ballot.deck)
            .ok_or_else(|| Refusal("unknown or closed deck".into()))?;
        // Step 3 of ballot intake: the presentation verifies for this context.
        if !self
            .verifier
            .verify(&ballot.deck, &ballot.presentation, &ballot.pseudonym)
        {
            return Err(Refusal(
                "presentation does not verify for this context".into(),
            ));
        }
        if ballot.votes.len() != deck.plan.statements as usize {
            return Err(Refusal("ballot length does not match the deck".into()));
        }
        if ballot.votes.iter().filter(|v| v.is_some()).count() > deck.plan.cap as usize {
            return Err(Refusal(
                "ballot carries more votes than the contribution cap".into(),
            ));
        }
        // AG-2: one counted ballot per nullifier. A different body under a known
        // nullifier before close replaces the earlier one and never adds a row;
        // an identical resubmission is idempotent (`ballot.md`).
        deck.ballots
            .insert(ballot.pseudonym.clone(), ballot.clone());
        let id = format!(
            "rcpt_{}",
            fake_hex(format!("{}/{}", ballot.deck, ballot.pseudonym).as_bytes())
        );
        self.tape.borrow_mut().see(
            "aggregator",
            "log",
            &format!("accepted ballot for deck {}", ballot.deck),
        );
        Ok(Receipt { id })
    }

    fn close(&mut self, deck_cid: &Cid, seed: u64) -> Result<Release, Refusal> {
        self.tape.borrow_mut().see("aggregator", "close", deck_cid);
        if self.released.contains(deck_cid) {
            return Err(Refusal("one release per deck".into()));
        }
        let deck = self
            .decks
            .remove(deck_cid)
            .ok_or_else(|| Refusal("unknown deck".into()))?;
        let (m, rows) = Self::matrix(&deck);
        let mut rng = ChaCha8Rng::seed_from_u64(seed);
        let plan = &deck.plan;
        let min_voters = deck.context_floors.min_voters.max(self.floors.min_voters) as f64;
        let eps = rho_to_eps(plan.rho, plan.delta.min(DELTA));
        let params = match self.tiering {
            Tiering::Research => DpParams {
                cap: Some(plan.cap as usize),
                bound: false,
                map_gate: None,
                common_gate: None,
                ..self.params
            },
            Tiering::Gated => DpParams {
                cap: Some(plan.cap as usize),
                bound: false,
                map_gate: Some(GATE_MAP),
                common_gate: Some(GATE_COMMON),
                ..self.params
            },
        };
        if m.n() == 0 {
            return Err(Refusal("no ballots".into()));
        }
        let a = dp_pipeline(&m, eps, &params, &mut rng);
        self.released.insert(deck_cid.clone());
        let split = params.split;
        // R6: below the minimum nothing unlocks; the tallies part's ρ was
        // still spent and the release is logged, final, without tables.
        let release = if a.n_hat < min_voters {
            Release {
                deck: deck_cid.clone(),
                rho: plan.rho * split.tally,
                delta: plan.delta,
                n_hat: None,
                parts: vec![],
                tallies: Tallies::default(),
                sigmas: a.sigmas.unwrap_or_default(),
                axes: None,
                group_tallies: vec![],
                rep: vec![],
                cons: vec![],
                signers: vec!["aggregator-leader".into(), "aggregator-helper".into()],
            }
        } else {
            let map_tier = !a.pcs.is_empty();
            let mut parts = vec!["tallies".to_string()];
            let mut rho = plan.rho * split.tally;
            if !a.cons.is_empty() || map_tier {
                parts.push("common-ground".into());
            }
            if map_tier {
                parts.extend(["map".to_string(), "groups".to_string()]);
                rho = plan.rho;
            }
            let axes = map_tier.then(|| Axes {
                sel: a.sel.clone(),
                pcs: a.pcs.clone(),
                mu: a.mu.clone(),
                centroids: a.centroids.clone(),
            });
            Release {
                deck: deck_cid.clone(),
                rho,
                delta: plan.delta,
                n_hat: Some(a.n_hat),
                parts,
                tallies: a.tallies.clone(),
                sigmas: a.sigmas.unwrap_or_default(),
                axes,
                group_tallies: a.group_tallies.clone(),
                rep: a.rep.clone(),
                cons: a.cons.clone(),
                signers: vec!["aggregator-leader".into(), "aggregator-helper".into()],
            }
        };
        self.last_analysis = Some(a);
        self.last_rows = rows;
        self.tape
            .borrow_mut()
            .see("aggregator", "release", &release);
        Ok(release)
    }
}
