//! The simulated world: phones, contexts, decks and the services behind the
//! ports, plus the flows of the ratchet (enroll, join, chat, promote, deal,
//! vote, close, digest) and the protocol oracles that run after them.
//!
//! The world is the only caller of a port. It counts every call per port so
//! the leak checker can fail a port that was called but never taped.

use std::collections::{BTreeMap, HashMap};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde_json::json;

use crate::data::{Vote, VoteMatrix};
use crate::fakes::{
    FakeAggregator, FakeBlobStore, FakeDelivery, FakeIssuer, FakeLedger, Scheme, SchemeVerifier,
    Tiering, new_scheme,
};
use crate::leak::{self, Kind, LeakReport, Secrets};
use crate::phone::{Charge, Phone};
use crate::ports::{
    Aggregator, Ballot, BlobStore, Cid, Delivery, Floors, Issuer, Ledger, Manifest, Receipt,
    Refusal, Release, ReleasePlan, Tape, TapeRef, blob_cid, fake_hex,
};

/// A context in the world.
#[derive(Clone, Debug)]
pub struct Context {
    /// Its manifest's CID.
    pub cid: Cid,
    /// Its manifest.
    pub manifest: Manifest,
    /// Its floors.
    pub floors: Floors,
    /// Its one channel (the simulator uses one per context for now).
    pub channel: String,
    /// Phones that joined, by index.
    pub members: Vec<usize>,
    /// Shared agents in the channel, by label.
    pub agents: Vec<String>,
}

/// A deck in the world.
#[derive(Clone, Debug)]
pub struct DeckRecord {
    /// Its manifest's CID.
    pub cid: Cid,
    /// Its manifest.
    pub manifest: Manifest,
    /// The context version it pins.
    pub context: Cid,
    /// Card texts.
    pub statements: Vec<String>,
    /// Phones whose ballots were accepted.
    pub voters: Vec<usize>,
    /// Whether the deck was closed.
    pub closed: bool,
    /// The release, once closed.
    pub release: Option<Release>,
}

/// A plaintext chat message the world remembers (phones' view, not the service's).
#[derive(Clone, Debug)]
pub struct Message {
    /// Channel.
    pub channel: String,
    /// Author's chat name, or `[agent] label`.
    pub author: String,
    /// Text.
    pub text: String,
    /// Sealed attachment reference, if any (`sk_…` key stays here).
    pub attachment: Option<(Cid, String)>,
}

/// The world.
pub struct World {
    /// Seed everything derives from.
    pub seed: u64,
    rng: ChaCha8Rng,
    /// Phones.
    pub phones: Vec<Phone>,
    /// The tape every service writes to.
    pub tape: TapeRef,
    /// Calls per port, counted by the world.
    pub calls: BTreeMap<&'static str, usize>,
    /// Registered secrets for the leak checker.
    pub secrets: Secrets,
    /// The credential scheme (issuer key material).
    pub scheme: Scheme,
    /// Services.
    pub aggregator: FakeAggregator,
    /// Ledger.
    pub ledger: FakeLedger,
    /// Issuer.
    pub issuer: FakeIssuer,
    /// Delivery.
    pub delivery: FakeDelivery,
    /// Store.
    pub store: FakeBlobStore,
    /// Contexts by CID.
    pub contexts: HashMap<Cid, Context>,
    /// Decks by CID.
    pub decks: BTreeMap<Cid, DeckRecord>,
    /// Every manifest the world produced, by CID.
    pub manifests: BTreeMap<Cid, Manifest>,
    /// Plaintext messages (phones' view).
    pub messages: Vec<Message>,
    /// Protocol violations found so far.
    pub violations: Vec<String>,
    /// Refusals that were expected and happened.
    pub expected_refusals: Vec<String>,
}

impl World {
    /// A world with protocol floors and the given tiering.
    pub fn new(seed: u64, tiering: Tiering) -> Self {
        let tape = Tape::shared();
        let floors = Floors::protocol();
        let scheme = new_scheme();
        Self {
            seed,
            rng: ChaCha8Rng::seed_from_u64(seed ^ 0x0077_0a1d_0000_0000_u64),
            phones: vec![],
            tape: tape.clone(),
            calls: BTreeMap::new(),
            secrets: Secrets::default(),
            scheme: scheme.clone(),
            aggregator: FakeAggregator::new(
                tape.clone(),
                floors,
                tiering,
                Box::new(SchemeVerifier(scheme.clone())),
            ),
            ledger: FakeLedger::new(tape.clone(), floors),
            issuer: FakeIssuer::new(tape.clone(), scheme),
            delivery: FakeDelivery::new(tape.clone()),
            store: FakeBlobStore::new(tape),
            contexts: HashMap::new(),
            decks: BTreeMap::new(),
            manifests: BTreeMap::new(),
            messages: vec![],
            violations: vec![],
            expected_refusals: vec![],
        }
    }

    /// The world's rng, for scenarios.
    pub fn rng(&mut self) -> &mut ChaCha8Rng {
        &mut self.rng
    }

    fn called(&mut self, port: &'static str) {
        *self.calls.entry(port).or_insert(0) += 1;
    }

    /// Create `n` phones and issue each a resident card. With an
    /// over-collecting verifier the phones refuse to apply (wave 2 hook; the
    /// world refuses, nothing is tested yet).
    pub fn enroll(&mut self, n: usize) -> Vec<usize> {
        let start = self.phones.len();
        for i in start..start + n {
            let mut p = Phone::new(i, self.seed);
            self.secrets
                .register(i, Kind::ChatKey, p.chat_name.as_bytes());
            self.secrets
                .register(i, Kind::HandCanary, p.hand_canary().as_bytes());
            self.secrets
                .register(i, Kind::DeviceKey, p.device_key().as_bytes());
            if self.issuer.over_collects {
                self.expected_refusals.push(format!(
                    "phone {i} refused to apply to an over-collecting verifier"
                ));
            } else {
                self.called("issuer");
                let sig = self
                    .issuer
                    .issue(&p.blind_request())
                    .expect("issuer signs blinded requests");
                p.receive_card(&sig);
                self.secrets.register(
                    i,
                    Kind::ResidentCard,
                    p.resident_card.as_ref().expect("card").as_bytes(),
                );
            }
            self.phones.push(p);
        }
        (start..start + n).collect()
    }

    fn register(&mut self, m: Manifest) -> Cid {
        let cid = m.cid();
        self.manifests.insert(cid.clone(), m);
        cid
    }

    /// Create a context with the given floors.
    pub fn create_context(&mut self, name: &str, floors: Floors) -> Cid {
        let m = Manifest {
            kind: "context".into(),
            authority: format!("authority/{name}"),
            version: 1,
            prev: None,
            refs: BTreeMap::new(),
            body: json!({ "name": name, "floors": floors, "visibility": "public", "channels": [format!("{name}/general")] }),
        };
        let cid = self.register(m.clone());
        self.contexts.insert(
            cid.clone(),
            Context {
                cid: cid.clone(),
                manifest: m,
                floors,
                channel: format!("{name}/general"),
                members: vec![],
                agents: vec![],
            },
        );
        cid
    }

    /// A phone joins a context: it joins the channel, which is an MLS
    /// membership event. Voting pseudonyms are per deck and derived when a
    /// deck is voted on; the membership proof travels only inside ballots.
    pub fn join(&mut self, phone: usize, context: &Cid) -> Result<(), Refusal> {
        if self.phones[phone].resident_card.is_none() {
            return Err(Refusal("no resident card".into()));
        }
        let ctx = self.contexts.get_mut(context).expect("context exists");
        ctx.members.push(phone);
        let channel = ctx.channel.clone();
        let dk = self.phones[phone].device_key();
        self.called("delivery");
        self.delivery.membership(&channel, &format!("join {dk}"))?;
        Ok(())
    }

    /// Add a shared agent to a context's channel: a visible membership event.
    pub fn add_agent(&mut self, context: &Cid, label: &str) {
        let ctx = self.contexts.get_mut(context).expect("context exists");
        ctx.agents.push(label.to_string());
        let channel = ctx.channel.clone();
        self.called("delivery");
        self.delivery
            .membership(
                &channel,
                &format!("join agent:{label} runs=member-hardware sponsor=authority/sponsor"),
            )
            .expect("membership event");
    }

    fn seal(&mut self, plaintext: &str) -> (String, String) {
        let key = format!("sk_{}", fake_hex(&self.rng.random::<u64>().to_le_bytes()));
        self.secrets
            .register(usize::MAX, Kind::SealedKey, key.as_bytes());
        let ct = format!("ct_{}", fake_hex(format!("{key}/{plaintext}").as_bytes()));
        (key, ct)
    }

    fn put_public(&mut self, bytes: &[u8]) -> Cid {
        let cid = blob_cid(bytes);
        self.called("store");
        self.store
            .put(&format!("pp_{}", fake_hex(cid.0.as_bytes())), &cid, bytes)
            .expect("store accepts");
        cid
    }

    fn send(&mut self, channel: &str, plaintext: &str) {
        let (_key, ct) = self.seal(plaintext);
        self.called("delivery");
        self.delivery
            .send(channel, &ct)
            .expect("delivery accepts ciphertext");
    }

    /// A phone posts a message in a context's channel, optionally with a sealed attachment.
    pub fn post(
        &mut self,
        context: &Cid,
        phone: usize,
        text: &str,
        attachment: Option<&str>,
    ) -> usize {
        let channel = self.contexts[context].channel.clone();
        let author = self.phones[phone].chat_name.clone();
        let attachment = attachment.map(|bytes| {
            let (key, ct) = self.seal(bytes);
            let cid = self.put_public(ct.as_bytes());
            (cid, key)
        });
        self.send(&channel, &format!("{author}: {text}"));
        self.messages.push(Message {
            channel,
            author,
            text: text.to_string(),
            attachment,
        });
        self.messages.len() - 1
    }

    /// An agent posts a labeled message.
    pub fn agent_post(&mut self, context: &Cid, label: &str, text: &str) {
        let channel = self.contexts[context].channel.clone();
        let author = format!("[agent] {label}");
        self.send(&channel, &format!("{author}: {text}"));
        self.messages.push(Message {
            channel,
            author,
            text: text.to_string(),
            attachment: None,
        });
    }

    /// Promote a message to a position on the issue map. The text goes to a
    /// public blob (public context); the manifest pins it by CID. The author's
    /// chat key is the manifest's signer (`authority`), never a body field.
    pub fn promote(&mut self, context: &Cid, message: usize, issue: &str) -> Cid {
        let text = self.messages[message].text.clone();
        let author = self.messages[message].author.clone();
        let cid = self.put_public(text.as_bytes());
        let mut refs = BTreeMap::new();
        refs.insert("context".to_string(), context.clone());
        refs.insert("text".to_string(), cid);
        let m = Manifest {
            kind: "position".into(),
            authority: author,
            version: 1,
            prev: None,
            refs,
            body: json!({ "kind": "position", "issue": issue }),
        };
        self.register(m)
    }

    /// Deal a deck in a context. Returns the deck's CID; the aggregator must
    /// accept it, otherwise the refusal is returned.
    pub fn deal(
        &mut self,
        context: &Cid,
        title: &str,
        statements: Vec<String>,
        plan: &ReleasePlan,
    ) -> Result<Cid, Refusal> {
        let ctx = self.contexts[context].clone();
        let list = statements.join("\n");
        let list_cid = self.put_public(list.as_bytes());
        let mut refs = BTreeMap::new();
        refs.insert("context".to_string(), context.clone());
        refs.insert("statements".to_string(), list_cid);
        let m = Manifest {
            kind: "deck".into(),
            authority: ctx.manifest.authority.clone(),
            version: 1,
            prev: None,
            refs,
            body: json!({ "title": title, "plan": plan }),
        };
        let cid = self.register(m.clone());
        self.called("aggregator");
        self.aggregator.open(&m, &ctx.manifest)?;
        self.decks.insert(
            cid.clone(),
            DeckRecord {
                cid: cid.clone(),
                manifest: m,
                context: context.clone(),
                statements,
                voters: vec![],
                closed: false,
                release: None,
            },
        );
        // The deck appears in its issue channel as a card to play from.
        self.send(&ctx.channel, &format!("deck dealt: {title}"));
        Ok(cid)
    }

    /// A phone checks the deck (reserving the plan's ρ on its shield), keeps
    /// the first K cards of its hand, builds its ballot (the entry becomes
    /// pending) and sends it; a receipt charges the entry. Returns the refusal
    /// if the phone or the aggregator refused.
    pub fn vote(
        &mut self,
        deck: &Cid,
        phone: usize,
        hand: Vec<Option<Vote>>,
    ) -> Result<(), Refusal> {
        let (manifest, context) = {
            let d = self
                .decks
                .get(deck)
                .ok_or_else(|| Refusal("unknown deck".into()))?;
            (d.manifest.clone(), d.context.clone())
        };
        let floors = self.contexts[&context].floors;
        if !self.contexts[&context].members.contains(&phone) {
            return Err(Refusal("phone has not joined the context".into()));
        }
        let plan = self.phones[phone].check_deck(&manifest, &floors)?;
        self.phones[phone].cast(deck, hand, plan.cap as usize);
        let ballot = self.phones[phone].ballot(deck)?;
        self.secrets
            .register(phone, Kind::Pseudonym, ballot.pseudonym.as_bytes());
        self.called("aggregator");
        self.aggregator.submit(&ballot)?;
        self.phones[phone].receipt(deck);
        let d = self.decks.get_mut(deck).expect("deck exists");
        if !d.voters.contains(&phone) {
            d.voters.push(phone);
        }
        Ok(())
    }

    /// A phone restores from its backup onto a new device: hands are lost,
    /// the shield is rebuilt as an upper bound over every deck of every
    /// context the phone joined (`shield.md`, restore), and the new device
    /// joins the channels.
    pub fn restore(&mut self, phone: usize) {
        let known: Vec<(Cid, f64)> = self
            .decks
            .values()
            .filter(|d| self.contexts[&d.context].members.contains(&phone))
            .map(|d| {
                (
                    d.cid.clone(),
                    Phone::plan_of(&d.manifest).expect("plan").rho,
                )
            })
            .collect();
        self.phones[phone].restore_from_backup(&known);
        let dk = self.phones[phone].device_key();
        self.secrets.register(phone, Kind::DeviceKey, dk.as_bytes());
        let channels: Vec<String> = self
            .contexts
            .values()
            .filter(|c| c.members.contains(&phone))
            .map(|c| c.channel.clone())
            .collect();
        for channel in channels {
            self.called("delivery");
            self.delivery
                .membership(&channel, &format!("join {dk}"))
                .expect("membership event");
        }
    }

    /// Submit a ballot the world did not build (adversarial hooks).
    pub fn submit_raw(&mut self, ballot: &Ballot) -> Result<Receipt, Refusal> {
        self.called("aggregator");
        self.aggregator.submit(ballot)
    }

    /// Close a deck: the aggregator releases, the ledger logs, a release
    /// manifest pins the deck, and a digest is posted back to the channel.
    pub fn close(&mut self, deck: &Cid, seed: u64) -> Result<Release, Refusal> {
        let (manifest, context) = {
            let d = self
                .decks
                .get(deck)
                .ok_or_else(|| Refusal("unknown deck".into()))?;
            (d.manifest.clone(), d.context.clone())
        };
        let ctx = self.contexts[&context].clone();
        self.called("aggregator");
        let release = self.aggregator.close(deck, seed)?;
        self.decks.get_mut(deck).expect("deck exists").closed = true;
        self.called("ledger");
        self.ledger.append(&release, &manifest, &ctx.manifest)?;
        let mut refs = BTreeMap::new();
        refs.insert("deck".to_string(), deck.clone());
        if !release.parts.is_empty() {
            let table = serde_json::to_string(&release.tallies).expect("tallies serialise");
            refs.insert("tables".to_string(), self.put_public(table.as_bytes()));
        }
        let m = Manifest {
            kind: "release".into(),
            authority: "aggregator-leader+aggregator-helper".into(),
            version: 1,
            prev: None,
            refs,
            body: json!({ "rho": release.rho, "delta": release.delta, "nHat": release.n_hat, "unlocked": release.parts, "final": true }),
        };
        self.register(m);
        let digest = match release.n_hat {
            Some(n) => format!(
                "release for deck {}: {} parts, {:.0} voters",
                deck,
                release.parts.len(),
                n
            ),
            None => format!("deck {deck} closed below the voter minimum: nothing published"),
        };
        if let Some(agent) = ctx.agents.first().cloned() {
            self.agent_post(&context, &agent, &digest);
        } else {
            self.send(&ctx.channel, &digest);
        }
        self.decks.get_mut(deck).expect("deck exists").release = Some(release.clone());
        Ok(release)
    }

    /// Phone-side groups for a released deck, as each phone would compute
    /// them from the published axes. `None` for phones without a hand or for
    /// releases without a map.
    pub fn phone_groups(&self, deck: &Cid) -> Vec<Option<usize>> {
        let d = &self.decks[deck];
        let Some(axes) = d.release.as_ref().and_then(|r| r.axes.as_ref()) else {
            return vec![None; d.voters.len()];
        };
        d.voters
            .iter()
            .map(|&i| self.phones[i].locate(deck, axes).map(|(_, g)| g))
            .collect()
    }

    /// Structural verification of every manifest the world produced. Bodies
    /// may carry no identity class and no sealed key; an author's chat key
    /// appears only as a position's `authority`.
    pub fn verify_manifests(&self) -> Vec<String> {
        let mut bad = vec![];
        for (cid, m) in &self.manifests {
            if m.version == 0 || (m.version == 1) != m.prev.is_none() {
                bad.push(format!("{cid}: bad version/prev"));
            }
            if ![
                "context", "deck", "release", "position", "issue", "argument",
            ]
            .contains(&m.kind.as_str())
            {
                bad.push(format!("{cid}: unknown type {}", m.kind));
            }
            for (name, r) in &m.refs {
                let known = self.manifests.contains_key(r)
                    || name == "text"
                    || name == "statements"
                    || name == "tables";
                if !known {
                    bad.push(format!("{cid}: dangling ref {name} -> {r}"));
                }
            }
            match m.kind.as_str() {
                "deck" => {
                    let Some(ctx) = m.refs.get("context").and_then(|c| self.contexts.get(c)) else {
                        bad.push(format!("{cid}: deck pins no context"));
                        continue;
                    };
                    match Phone::plan_of(m) {
                        Ok(plan) => {
                            if plan.rho > ctx.floors.max_rho + 1e-12
                                || plan.delta > ctx.floors.max_delta
                                || plan.cap == 0
                            {
                                bad.push(format!("{cid}: release plan breaks the context floors"));
                            }
                        }
                        Err(e) => bad.push(format!("{cid}: {e}")),
                    }
                }
                "release"
                    if m.refs
                        .get("deck")
                        .is_none_or(|d| !self.decks.contains_key(d)) =>
                {
                    bad.push(format!("{cid}: release pins no deck"));
                }
                _ => {}
            }
            let body = m.body.to_string();
            if ["rc_", "vp_", "cn_", "sk_", "hc_", "an_"]
                .iter()
                .any(|p| body.contains(p))
            {
                bad.push(format!(
                    "{cid}: manifest body carries an identity, a canary or a sealed key"
                ));
            }
            if m.kind != "position" && m.authority.starts_with("cn_") {
                bad.push(format!("{cid}: only positions are signed by a chat key"));
            }
        }
        bad
    }

    /// Run the protocol oracles: manifests verify, releases respect floors,
    /// the ledger chains, every closed deck has exactly one ledger entry, no
    /// shield overspends or refunds, no double counting.
    pub fn protocol_checks(&mut self) -> Vec<String> {
        let mut v = self.verify_manifests();
        if let Err(e) = self.ledger.verify() {
            v.push(format!("ledger: {e}"));
        }
        let floors = Floors::protocol();
        for d in self.decks.values() {
            if !d.closed {
                continue;
            }
            if self
                .ledger
                .entries
                .iter()
                .filter(|e| e.deck == d.cid)
                .count()
                != 1
            {
                v.push(format!("deck {}: not exactly one ledger entry", d.cid));
            }
            let plan = Phone::plan_of(&d.manifest).expect("plan");
            if let Some(r) = &d.release {
                if r.rho > floors.max_rho + 1e-12 || r.rho > plan.rho + 1e-12 {
                    v.push(format!(
                        "deck {}: release above the floor or the plan",
                        d.cid
                    ));
                }
                if r.n_hat.is_some_and(|n| n < floors.min_voters as f64) {
                    v.push(format!(
                        "deck {}: tables published below the voter minimum",
                        d.cid
                    ));
                }
                if r.n_hat.is_none() && !r.parts.is_empty() {
                    v.push(format!(
                        "deck {}: parts unlocked without a voter count",
                        d.cid
                    ));
                }
            }
            // Every voter carries exactly one committed entry for the deck at the
            // plan's ρ, never a reservation that went away after a send.
            for &i in &d.voters {
                let entries: Vec<_> = self.phones[i]
                    .shield
                    .committed()
                    .filter(|e| e.deck == d.cid)
                    .collect();
                if entries.len() != 1
                    || (entries[0].rho - plan.rho).abs() > 1e-12
                    || entries[0].state == Charge::Pending
                {
                    v.push(format!(
                        "deck {}: phone {i} shield entries {entries:?}, plan {}",
                        d.cid, plan.rho
                    ));
                }
            }
        }
        for p in &self.phones {
            if p.shield.spent_rho() > p.floors.yearly_shield_rho + 1e-12 {
                v.push(format!(
                    "phone {}: shield overspent ({:.3})",
                    p.idx,
                    p.shield.spent_rho()
                ));
            }
        }
        v.sort();
        self.violations.extend(v.clone());
        v
    }

    /// Run the leak checker over everything services saw.
    pub fn leak_report(&self) -> LeakReport {
        leak::check(&self.tape.borrow(), &self.secrets, &self.calls)
    }

    /// The vote matrix the aggregator counted for a deck, in its row order,
    /// with the phone index per row. For oracles only. A phone that restored
    /// from backup after voting has no hand; its row is left empty.
    pub fn counted_matrix(&self, deck: &Cid) -> (VoteMatrix, Vec<usize>) {
        let d = &self.decks[deck];
        let by_pseudonym: HashMap<String, usize> = d
            .voters
            .iter()
            .filter_map(|&i| self.phones[i].pseudonyms.get(deck).map(|p| (p.clone(), i)))
            .collect();
        let rows: Vec<usize> = self
            .aggregator
            .last_rows
            .iter()
            .map(|p| by_pseudonym[p])
            .collect();
        let c = d.statements.len();
        let mut m = VoteMatrix::new(format!("deck {}", d.cid), rows.len(), c);
        for (r, &i) in rows.iter().enumerate() {
            if let Some(hand) = self.phones[i].hands.get(&d.cid) {
                for (j, v) in hand.votes.iter().enumerate().take(c) {
                    m.set(r, j, *v);
                }
            }
        }
        (m, rows)
    }
}

/// A release plan for a deck of `statements` cards at ρ with the research
/// defaults (cap 60, all four parts).
pub fn research_plan(rho: f64, statements: usize) -> ReleasePlan {
    ReleasePlan {
        rho,
        delta: 1e-6,
        parts: vec![
            "tallies".into(),
            "common-ground".into(),
            "map".into(),
            "groups".into(),
        ],
        cap: 60,
        statements: statements as u32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::synthetic::{SyntheticSpec, generate};

    fn world_with_deck(n: usize, tiering: Tiering) -> (World, Vec<usize>, Cid, Cid, VoteMatrix) {
        let m = generate(&SyntheticSpec::sized(n), 1);
        let mut w = World::new(7, tiering);
        let phones = w.enroll(m.n());
        let ctx = w.create_context("test", Floors::protocol());
        for &p in &phones {
            w.join(p, &ctx).unwrap();
        }
        let statements: Vec<String> = (0..m.c()).map(|j| format!("statement {j}")).collect();
        let deck = w
            .deal(&ctx, "deck", statements, &research_plan(0.254, m.c()))
            .unwrap();
        (w, phones, ctx, deck, m)
    }

    #[test]
    fn a_deck_runs_end_to_end_and_leaks_nothing() {
        let (mut w, phones, _ctx, deck, m) = world_with_deck(150, Tiering::Research);
        for (i, &p) in phones.iter().enumerate() {
            w.vote(&deck, p, m.row(i).to_vec()).unwrap();
        }
        let r = w.close(&deck, 1).unwrap();
        assert!(r.n_hat.unwrap() > 100.0);
        assert!(w.protocol_checks().is_empty(), "{:?}", w.violations);
        let leak = w.leak_report();
        assert!(leak.passed(), "{:?}", leak.violations);
        assert!(
            leak.calls_by_service.len() == 5,
            "{:?}",
            leak.calls_by_service
        );
        // Phone-side groups equal what the pipeline computed centrally.
        let central = w.aggregator.last_analysis.as_ref().unwrap().groups.clone();
        let (_, rows) = w.counted_matrix(&deck);
        let axes = r.axes.as_ref().unwrap();
        for (row, &i) in rows.iter().enumerate() {
            let (_, g) = w.phones[i].locate(&deck, axes).unwrap();
            assert_eq!(g, central[row], "phone {i}");
        }
        // Every voter's shield entry is charged at the plan's ρ.
        assert!(
            w.phones
                .iter()
                .all(|p| p.shield.entries.iter().all(|e| e.state == Charge::Charged))
        );
    }

    #[test]
    fn a_forged_or_mixed_ballot_is_refused() {
        let (mut w, phones, _ctx, deck, _m) = world_with_deck(20, Tiering::Research);
        let cards = w.decks[&deck].statements.len();
        let forged = Ballot {
            deck: deck.clone(),
            pseudonym: "vp_deadbeefdeadbeef".into(),
            presentation: "zk_0000000000000000".into(),
            votes: vec![None; cards],
        };
        assert!(w.submit_raw(&forged).is_err());
        // A real nullifier with someone else's presentation is refused too.
        let a = w.phones[phones[0]].pseudonym_for(&deck).unwrap();
        let b = w.phones[phones[1]].presentation(&deck).unwrap();
        let mixed = Ballot {
            deck: deck.clone(),
            pseudonym: a,
            presentation: b,
            votes: vec![None; cards],
        };
        assert!(w.submit_raw(&mixed).is_err());
        assert_eq!(w.aggregator.ballots(&deck), 0);
    }

    #[test]
    fn a_restore_loses_the_hand_and_keeps_the_charge() {
        let (mut w, phones, _ctx, deck, m) = world_with_deck(20, Tiering::Research);
        w.vote(&deck, phones[0], m.row(0).to_vec()).unwrap();
        w.restore(phones[0]);
        assert!(w.phones[phones[0]].hands.is_empty());
        let e = &w.phones[phones[0]].shield.entries;
        assert_eq!(e.len(), 1);
        assert_eq!(e[0].state, Charge::Estimated);
        // The same nullifier is derived again, so a re-vote replaces, never adds.
        w.vote(&deck, phones[0], m.row(0).to_vec()).unwrap();
        assert_eq!(w.aggregator.ballots(&deck), 1);
        assert_eq!(w.phones[phones[0]].shield.entries.len(), 1);
    }

    #[test]
    fn a_below_minimum_close_logs_a_release_with_nothing_unlocked() {
        let (mut w, phones, _ctx, deck, m) = world_with_deck(30, Tiering::Gated);
        for (i, &p) in phones.iter().enumerate() {
            w.vote(&deck, p, m.row(i).to_vec()).unwrap();
        }
        let r = w.close(&deck, 2).unwrap();
        assert!(r.n_hat.is_none() && r.parts.is_empty(), "{r:?}");
        assert_eq!(w.ledger.entries.len(), 1);
        assert!(r.rho < 0.254);
        assert!(w.protocol_checks().is_empty(), "{:?}", w.violations);
        assert!(w.leak_report().passed());
    }

    #[test]
    fn a_plan_above_the_floor_is_refused_everywhere() {
        let mut w = World::new(8, Tiering::Research);
        let phones = w.enroll(5);
        let ctx = w.create_context("test", Floors::protocol());
        for &p in &phones {
            w.join(p, &ctx).unwrap();
        }
        let err = w
            .deal(&ctx, "deck", vec!["a".into()], &research_plan(0.5, 1))
            .unwrap_err();
        assert!(err.0.contains("floors"), "{err}");
    }
}
