//! A simulated phone: its three identities, its hand per deck, its shield and
//! its floors. Phones are data structures the world drives; nothing here talks
//! to a service directly, so the tape never sees what a phone keeps.
//!
//! Draft 0.1 (`ballot.md`, `shield.md`) has one voting device per person and
//! no transfer of a hand or a shield: a device change is a backup restore
//! that loses the hands and rebuilds the shield as an upper bound.

use std::collections::HashMap;

use serde::Serialize;

use crate::data::Vote;
use crate::fakes::identity::{card_from, nullifier_of, presentation_of};
use crate::ports::{
    Axes, Ballot, Cid, Floors, Manifest, Refusal, ReleasePlan, fake_hash, fake_hex,
};

/// State of one shield entry (`shield.md` S3–S10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Charge {
    /// Deck opened on this phone, nothing sent yet. Drops if nothing is ever sent.
    Reserved,
    /// Ballot bytes handed to the network. Never refunded, whatever the answer.
    Pending,
    /// A receipt came back.
    Charged,
    /// Rebuilt from a backup as an upper bound (`chargedAt` = the deck's close).
    Estimated,
}

/// One shield entry.
#[derive(Clone, Debug, Serialize)]
pub struct ShieldEntry {
    /// The deck.
    pub deck: Cid,
    /// ρ.
    pub rho: f64,
    /// State.
    pub state: Charge,
}

/// The shield: yearly privacy budget, tracked only on the phone. Every entry
/// counts against the remaining budget, reserved ones included.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Shield {
    /// Entries, one per deck.
    pub entries: Vec<ShieldEntry>,
}

impl Shield {
    /// ρ counted against the budget.
    pub fn spent_rho(&self) -> f64 {
        self.entries.iter().map(|e| e.rho).sum()
    }

    /// Entries that are not merely reserved.
    pub fn committed(&self) -> impl Iterator<Item = &ShieldEntry> {
        self.entries.iter().filter(|e| e.state != Charge::Reserved)
    }

    fn entry_mut(&mut self, deck: &Cid) -> Option<&mut ShieldEntry> {
        self.entries.iter_mut().find(|e| e.deck == *deck)
    }
}

/// A hand: the phone's own votes in a deck, plus a canary secret that must
/// never appear anywhere off the phone (`storage.md` §10).
#[derive(Clone, Debug, Serialize)]
pub struct Hand {
    /// One entry per card, after the contribution cap.
    pub votes: Vec<Option<Vote>>,
    /// A per-phone secret seeded into every hand; registered with the leak checker.
    pub canary: String,
}

/// One simulated phone.
#[derive(Clone, Debug)]
pub struct Phone {
    /// Simulator index. Never shown to a service.
    pub idx: usize,
    secret: u64,
    /// Device generation; a restore from backup bumps it.
    pub device: u32,
    /// The resident card (`rc_…`), derived from the issuer's blind signature.
    pub resident_card: Option<String>,
    /// The chat name (`cn_…`), also the key that signs authored objects.
    pub chat_name: String,
    /// Per-deck voting pseudonyms (`vp_…`), derived from the card.
    pub pseudonyms: HashMap<Cid, String>,
    /// Hands, one per deck.
    pub hands: HashMap<Cid, Hand>,
    /// The shield.
    pub shield: Shield,
    /// Floors this phone enforces (protocol minimums or stricter).
    pub floors: Floors,
    /// Whether this phone's client has been modified (wave 2 adversarial hook).
    pub modified: bool,
}

impl Phone {
    /// A phone with a fresh secret derived from the world seed and its index.
    pub fn new(idx: usize, world_seed: u64) -> Self {
        let secret = fake_hash(format!("phone-secret/{world_seed}/{idx}").as_bytes());
        Self {
            idx,
            secret,
            device: 1,
            resident_card: None,
            chat_name: format!("cn_{}", fake_hex(format!("chat/{secret}").as_bytes())),
            pseudonyms: HashMap::new(),
            hands: HashMap::new(),
            shield: Shield::default(),
            floors: Floors::protocol(),
            modified: false,
        }
    }

    /// Device key label (`dk_…`), changes on a restore to a new device.
    pub fn device_key(&self) -> String {
        format!(
            "dk_{}",
            fake_hex(format!("device/{}/{}", self.secret, self.device).as_bytes())
        )
    }

    /// The hand canary (`hc_…`): a secret no service may ever see.
    pub fn hand_canary(&self) -> String {
        format!(
            "hc_{}",
            fake_hex(format!("canary/{}", self.secret).as_bytes())
        )
    }

    /// A blinded issuance request: the issuer sees this, never the card.
    pub fn blind_request(&self) -> String {
        format!(
            "blind_{}",
            fake_hex(format!("blind/{}", self.secret).as_bytes())
        )
    }

    /// Unblind: derive the resident card from the issuer's signature.
    pub fn receive_card(&mut self, issuer_signature: &str) {
        self.resident_card = Some(card_from(issuer_signature, &self.blind_request()));
    }

    /// The pseudonym for a deck: a nullifier scoped to the deck lineage, so
    /// two decks never share one and a restored device derives the same one.
    pub fn pseudonym_for(&mut self, deck: &Cid) -> Result<String, Refusal> {
        let card = self
            .resident_card
            .clone()
            .ok_or_else(|| Refusal("no resident card".into()))?;
        Ok(self
            .pseudonyms
            .entry(deck.clone())
            .or_insert_with(|| nullifier_of(&card, deck))
            .clone())
    }

    /// A membership presentation for a deck, bound to its nullifier.
    pub fn presentation(&mut self, deck: &Cid) -> Result<String, Refusal> {
        let nullifier = self.pseudonym_for(deck)?;
        let card = self
            .resident_card
            .as_ref()
            .expect("card exists after pseudonym");
        Ok(presentation_of(card, deck, &nullifier))
    }

    /// Restore from a backup onto a new device: the card survives, every hand
    /// is lost, and the shield is rebuilt as an upper bound with an estimated
    /// entry for every deck in `known_decks` (every deck of every backed-up
    /// context whose close is within 365 days or in the future).
    pub fn restore_from_backup(&mut self, known_decks: &[(Cid, f64)]) {
        self.device += 1;
        self.hands.clear();
        self.pseudonyms.clear();
        let mut entries = Vec::with_capacity(known_decks.len());
        for (deck, rho) in known_decks {
            entries.push(ShieldEntry {
                deck: deck.clone(),
                rho: *rho,
                state: Charge::Estimated,
            });
        }
        self.shield.entries = entries;
    }

    /// The deck's release plan, parsed from its body.
    pub fn plan_of(deck: &Manifest) -> Result<ReleasePlan, Refusal> {
        let v = deck
            .body
            .get("plan")
            .ok_or_else(|| Refusal("deck has no plan".into()))?;
        serde_json::from_value(v.clone()).map_err(|e| Refusal(format!("bad plan: {e}")))
    }

    /// Check a deck against this phone's floors and shield and reserve the
    /// plan's ρ. A refusal means the phone sits the deck out (S3, S4).
    pub fn check_deck(
        &mut self,
        deck: &Manifest,
        context_floors: &Floors,
    ) -> Result<ReleasePlan, Refusal> {
        if deck.kind != "deck" {
            return Err(Refusal(format!("not a deck: {}", deck.kind)));
        }
        if !deck.refs.contains_key("context") {
            return Err(Refusal("deck pins no context".into()));
        }
        let plan = Self::plan_of(deck)?;
        let cid = deck.cid();
        if self.shield.entry_mut(&cid).is_some() {
            return Ok(plan);
        }
        if !self.modified {
            let floors = if context_floors.allows(&self.floors) {
                self.floors
            } else {
                *context_floors
            };
            if plan.rho > floors.max_rho + 1e-12 {
                return Err(Refusal(format!(
                    "plan rho {} above floor {}",
                    plan.rho, floors.max_rho
                )));
            }
            if plan.delta > floors.max_delta {
                return Err(Refusal(format!(
                    "plan delta {} above floor {}",
                    plan.delta, floors.max_delta
                )));
            }
            if plan.cap == 0 {
                return Err(Refusal("plan declares no contribution cap".into()));
            }
            if self.shield.spent_rho() + plan.rho > floors.yearly_shield_rho + 1e-12 {
                return Err(Refusal("shield exhausted".into()));
            }
        }
        self.shield.entries.push(ShieldEntry {
            deck: cid,
            rho: plan.rho,
            state: Charge::Reserved,
        });
        Ok(plan)
    }

    /// Drop a reservation. Only possible while nothing was ever sent (S7).
    pub fn drop_reservation(&mut self, deck: &Cid) -> bool {
        let before = self.shield.entries.len();
        self.shield
            .entries
            .retain(|e| !(e.deck == *deck && e.state == Charge::Reserved));
        self.shield.entries.len() < before
    }

    /// The phone's own deal order for a deck (`deck.md`, `order` = 0): a
    /// permutation seeded from its secret, never transmitted.
    pub fn deal_order(&self, deck: &Cid, cards: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..cards).collect();
        let mut state = fake_hash(format!("order/{}/{}", self.secret, deck).as_bytes());
        for i in (1..cards).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let j = (state % (i as u64 + 1)) as usize;
            order.swap(i, j);
        }
        order
    }

    /// Record the hand for a deck, keeping the first `cap` cards cast in the
    /// phone's own deal order (`ballot.md`: never a random subset drawn later).
    pub fn cast(&mut self, deck: &Cid, mut votes: Vec<Option<Vote>>, cap: usize) {
        let order = self.deal_order(deck, votes.len());
        let mut kept = 0;
        for &j in &order {
            if votes[j].is_some() {
                if kept >= cap {
                    votes[j] = None;
                } else {
                    kept += 1;
                }
            }
        }
        let canary = self.hand_canary();
        self.hands.insert(deck.clone(), Hand { votes, canary });
    }

    /// Build the ballot for a deck and mark the shield entry pending: the
    /// bytes are about to leave and will never be refunded (S5–S7).
    pub fn ballot(&mut self, deck: &Cid) -> Result<Ballot, Refusal> {
        let votes = self
            .hands
            .get(deck)
            .map(|h| h.votes.clone())
            .ok_or_else(|| Refusal("no hand for deck".into()))?;
        let pseudonym = self.pseudonym_for(deck)?;
        let presentation = self.presentation(deck)?;
        let Some(e) = self.shield.entry_mut(deck) else {
            return Err(Refusal("no shield entry: deck was not checked".into()));
        };
        if e.state == Charge::Reserved {
            e.state = Charge::Pending;
        }
        Ok(Ballot {
            deck: deck.clone(),
            pseudonym,
            presentation,
            votes,
        })
    }

    /// A receipt came back: the entry is charged.
    pub fn receipt(&mut self, deck: &Cid) {
        if let Some(e) = self.shield.entry_mut(deck) {
            e.state = Charge::Charged;
        }
    }

    /// Place this phone on a release's published axes and pick its group:
    /// the phone-side half of the map, never sent anywhere. Returns `None`
    /// when the phone has no hand for the deck.
    pub fn locate(&self, deck: &Cid, axes: &Axes) -> Option<([f64; 2], usize)> {
        let hand = &self.hands.get(deck)?.votes;
        let mut q = [0.0, 0.0];
        let mut nv = 0usize;
        for (t, &j) in axes.sel.iter().enumerate() {
            if let Some(v) = hand.get(j).copied().flatten() {
                let z = v.value() - axes.mu[j];
                q[0] += z * axes.pcs[t][0];
                q[1] += z * axes.pcs[t][1];
                nv += 1;
            }
        }
        let scale = (axes.sel.len() as f64 / nv.max(1) as f64).sqrt();
        let p = [q[0] * scale, q[1] * scale];
        let mut best = (0usize, f64::INFINITY);
        for (g, c) in axes.centroids.iter().enumerate() {
            let d = (p[0] - c[0]).powi(2) + (p[1] - c[1]).powi(2);
            if d < best.1 {
                best = (g, d);
            }
        }
        Some((p, best.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudonyms_are_per_deck_and_survive_a_restore() {
        let mut p = Phone::new(0, 1);
        p.receive_card("isig_x");
        let a = Cid("fakecid_a".into());
        let b = Cid("fakecid_b".into());
        let pa = p.pseudonym_for(&a).unwrap();
        assert_ne!(pa, p.pseudonym_for(&b).unwrap());
        let dk1 = p.device_key();
        p.cast(&a, vec![Some(Vote::Agree)], 60);
        p.restore_from_backup(&[(a.clone(), 0.254)]);
        assert_ne!(dk1, p.device_key());
        assert!(p.hands.is_empty());
        assert_eq!(p.pseudonym_for(&a).unwrap(), pa);
        assert_eq!(p.shield.entries[0].state, Charge::Estimated);
        assert!((p.shield.spent_rho() - 0.254).abs() < 1e-12);
    }

    #[test]
    fn the_cap_keeps_the_first_k_cards_in_deal_order() {
        let mut p = Phone::new(2, 1);
        p.receive_card("isig_x");
        let d = Cid("fakecid_d".into());
        p.cast(&d, vec![Some(Vote::Agree); 10], 4);
        let hand = &p.hands[&d].votes;
        assert_eq!(hand.iter().filter(|v| v.is_some()).count(), 4);
        let order = p.deal_order(&d, 10);
        assert!(order[..4].iter().all(|&j| hand[j].is_some()));
    }

    #[test]
    fn no_card_means_no_pseudonym_or_ballot() {
        let mut p = Phone::new(3, 1);
        let d = Cid("fakecid_d".into());
        assert!(p.pseudonym_for(&d).is_err());
        p.cast(&d, vec![None], 60);
        assert!(p.ballot(&d).is_err());
    }
}
