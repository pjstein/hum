//! The ports: the interfaces the simulated world talks to services through,
//! the sim-side object types that cross them, and the tape that records what
//! every service saw. Wave 1 workstreams implement these traits over their
//! real crates and services (see `docs/specs/simulator.md`, "How wave 1 plugs
//! in"); `fakes/` holds the wave 0 stand-ins.
//!
//! Object types here are simulator stand-ins shaped like the manifest spec's
//! JSON view. They are replaced by the `hum-manifest` types when those land;
//! until then the fake CID is a labelled non-cryptographic hash.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::rc::Rc;

use serde::{Deserialize, Serialize};

use crate::data::Vote;
use crate::pipeline::{Rep, Sigmas, Tallies};

/// A content ID. In the simulator this is `fakecid_` plus a non-cryptographic
/// hash of the canonical JSON; it exists so references can be pinned and
/// checked structurally, not so anyone can trust it.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Cid(pub String);

impl std::fmt::Display for Cid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Non-cryptographic, deterministic 64-bit hash for fake identifiers.
/// Never use outside `sim/`.
pub fn fake_hash(bytes: &[u8]) -> u64 {
    // FNV-1a: stable across Rust versions, unlike `DefaultHasher`.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Hex of `fake_hash`.
pub fn fake_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fake_hash(bytes))
}

/// Privacy floors, as the manifest spec's "Privacy floors" section lists them.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct Floors {
    /// Largest ρ a single release may spend.
    pub max_rho: f64,
    /// Largest δ.
    pub max_delta: f64,
    /// Fewest noised voters needed to publish.
    pub min_voters: u64,
    /// Releases per deck.
    pub releases_per_deck: u32,
    /// Yearly shield per person, in ρ.
    pub yearly_shield_rho: f64,
}

impl Floors {
    /// Draft 0.1 protocol minimums: ρ ≤ 0.254, δ ≤ 10⁻⁶, 100 voters, one
    /// release per deck, yearly shield ε 20 (ρ ≈ 4.4).
    pub fn protocol() -> Self {
        Self {
            max_rho: 0.254,
            max_delta: 1e-6,
            min_voters: 100,
            releases_per_deck: 1,
            yearly_shield_rho: crate::pipeline::accounting::eps_to_rho(20.0, 1e-6),
        }
    }

    /// True when `other` is at least as strict on every floor.
    pub fn allows(&self, other: &Floors) -> bool {
        other.max_rho <= self.max_rho + 1e-12
            && other.max_delta <= self.max_delta
            && other.min_voters >= self.min_voters
            && other.releases_per_deck <= self.releases_per_deck
            && other.yearly_shield_rho <= self.yearly_shield_rho + 1e-12
    }
}

/// A release plan, the deck body's `plan` (a simplified shape; see the spec).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct ReleasePlan {
    /// ρ to spend.
    pub rho: f64,
    /// δ.
    pub delta: f64,
    /// Parts by tier, in the order they unlock.
    pub parts: Vec<String>,
    /// Contribution cap.
    pub cap: u32,
    /// How many statements the deck has.
    pub statements: u32,
}

/// A manifest in the simulator: the envelope fields that matter structurally
/// plus a JSON body. Signatures are represented by the authority name only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Manifest {
    /// Registry type (`context`, `deck`, `release`, `position`, …).
    #[serde(rename = "type")]
    pub kind: String,
    /// Authority that signs it (a label in the simulator).
    pub authority: String,
    /// Version, from 1.
    pub version: u32,
    /// Previous version's CID.
    pub prev: Option<Cid>,
    /// Pinned references.
    pub refs: BTreeMap<String, Cid>,
    /// Body.
    pub body: serde_json::Value,
}

impl Manifest {
    /// Compute the fake CID over the canonical JSON of the envelope.
    pub fn cid(&self) -> Cid {
        let bytes = serde_json::to_vec(self).expect("manifest serialises");
        Cid(format!("fakecid_{}", fake_hex(&bytes)))
    }
}

/// A ballot: everything a phone sends to an aggregator for one deck. The
/// credential is the ballot itself (`services.md`, "Ballot intake"): a
/// membership presentation, the per-deck nullifier, and the votes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Ballot {
    /// The deck version this ballot answers.
    pub deck: Cid,
    /// The per-deck voting pseudonym (nullifier, `vp_…`).
    pub pseudonym: String,
    /// The membership presentation (`zk_…`), verified by the aggregator.
    pub presentation: String,
    /// One entry per card, `None` for cards not voted on.
    pub votes: Vec<Option<Vote>>,
}

/// What the aggregator hands back for a ballot.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Receipt {
    /// Opaque receipt id.
    pub id: String,
}

/// Published axes and centroids, enough for a phone to place itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Axes {
    /// Statements the axes cover.
    pub sel: Vec<usize>,
    /// Two axes per selected statement.
    pub pcs: Vec<[f64; 2]>,
    /// Column means used for centring (post-processing of the tallies).
    pub mu: Vec<f64>,
    /// Group centroids in projection space.
    pub centroids: Vec<[f64; 2]>,
}

/// A release: the only thing that leaves aggregation. Every field is a sum
/// over participants or post-processing of sums.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Release {
    /// Deck version it reports on.
    pub deck: Cid,
    /// ρ spent.
    pub rho: f64,
    /// δ.
    pub delta: f64,
    /// Noised participant count; absent when nothing unlocked (`release.md` R6).
    pub n_hat: Option<f64>,
    /// Parts actually released (`unlocked`). Empty for a below-minimum release.
    pub parts: Vec<String>,
    /// Public tallies.
    pub tallies: Tallies,
    /// Published noise levels.
    pub sigmas: Sigmas,
    /// Axes and centroids, when the map tier was released.
    pub axes: Option<Axes>,
    /// Per-group tallies, when released.
    pub group_tallies: Vec<Tallies>,
    /// Representative statements per group (post-processing).
    pub rep: Vec<Vec<Rep>>,
    /// Consensus statements (post-processing).
    pub cons: Vec<usize>,
    /// Which aggregators signed (labels).
    pub signers: Vec<String>,
}

/// A refusal from a service or a phone, with the floor or rule that failed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Refusal(pub String);

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Refusal {}

/// One thing a service saw.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    /// Which service.
    pub service: &'static str,
    /// Which operation (or `log`).
    pub op: &'static str,
    /// The payload as JSON text (a readable view).
    pub payload: String,
    /// The raw bytes the service saw. Equal to `payload` unless the caller
    /// recorded binary bytes with `see_bytes`. The leak checker scans both.
    #[serde(skip)]
    pub raw: Vec<u8>,
}

/// Everything every service saw, in order. The leak checker reads it.
#[derive(Debug, Default)]
pub struct Tape {
    /// Records in arrival order.
    pub records: Vec<Record>,
}

/// Shared handle to the tape.
pub type TapeRef = Rc<RefCell<Tape>>;

impl Tape {
    /// A fresh shared tape.
    pub fn shared() -> TapeRef {
        Rc::new(RefCell::new(Tape::default()))
    }

    /// Record that `service` saw `payload` in `op`.
    pub fn see<T: Serialize + ?Sized>(
        &mut self,
        service: &'static str,
        op: &'static str,
        payload: &T,
    ) {
        let payload = serde_json::to_string(payload).expect("payload serialises");
        let raw = payload.clone().into_bytes();
        self.records.push(Record {
            service,
            op,
            payload,
            raw,
        });
    }

    /// Record that `service` saw raw `bytes` in `op`, with a JSON view beside them.
    pub fn see_bytes<T: Serialize + ?Sized>(
        &mut self,
        service: &'static str,
        op: &'static str,
        view: &T,
        bytes: &[u8],
    ) {
        let payload = serde_json::to_string(view).expect("payload serialises");
        let mut raw = payload.clone().into_bytes();
        raw.extend_from_slice(bytes);
        self.records.push(Record {
            service,
            op,
            payload,
            raw,
        });
    }

    /// Records per service.
    pub fn count_by_service(&self) -> std::collections::BTreeMap<&'static str, usize> {
        let mut m = std::collections::BTreeMap::new();
        for r in &self.records {
            *m.entry(r.service).or_insert(0) += 1;
        }
        m
    }
}

/// The services the world routes to, by the name they appear under on the tape.
pub const SERVICES: [&str; 5] = ["aggregator", "ledger", "issuer", "delivery", "store"];

/// Aggregator port: what `hum-release` behind the aggregator service will
/// implement for the simulator (W1 aggregation).
pub trait Aggregator {
    /// Accept a deck for voting after verifying it.
    fn open(&mut self, deck: &Manifest, context: &Manifest) -> Result<(), Refusal>;
    /// Accept one ballot. One per pseudonym per deck.
    fn submit(&mut self, ballot: &Ballot) -> Result<Receipt, Refusal>;
    /// Close the deck and produce its one release.
    fn close(&mut self, deck: &Cid, seed: u64) -> Result<Release, Refusal>;
}

/// Ledger port (W1 ledger and open data).
pub trait Ledger {
    /// Append a release after checking it against its deck and floors.
    fn append(
        &mut self,
        release: &Release,
        deck: &Manifest,
        context: &Manifest,
    ) -> Result<u64, Refusal>;
    /// Verify the whole chain; returns the number of entries.
    fn verify(&self) -> Result<u64, Refusal>;
}

/// Credential issuer port (W1 identity). There is no verifier service:
/// a presentation is generated on the phone and checked by whoever receives
/// it (the aggregator, on a ballot) with the issuer's public key material,
/// never by a service that also holds evidence (`design.md`, who sees what).
pub trait Issuer {
    /// Issue a resident card for a blinded request; the issuer never sees the card.
    fn issue(&mut self, blinded_request: &str) -> Result<String, Refusal>;
}

/// Public verification of a presentation, as the issuer's public key gives
/// it. Implemented by the credential scheme, not by a service.
pub trait PresentationVerifier {
    /// True when `presentation` proves membership for `nullifier` under `deck`.
    fn verify(&self, deck: &Cid, presentation: &str, nullifier: &str) -> bool;
}

/// Delivery port (W1 chat): carries sealed messages per channel.
pub trait Delivery {
    /// Deliver ciphertext to a channel.
    fn send(&mut self, channel: &str, ciphertext: &str) -> Result<(), Refusal>;
    /// A membership change on a channel (visible by design).
    fn membership(&mut self, channel: &str, event: &str) -> Result<(), Refusal>;
}

/// Blob store port (W1 storage).
pub trait BlobStore {
    /// Put bytes under a CID with an anonymous token.
    fn put(&mut self, token: &str, cid: &Cid, bytes: &[u8]) -> Result<(), Refusal>;
    /// Get bytes by CID.
    fn get(&mut self, token: &str, cid: &Cid) -> Result<Vec<u8>, Refusal>;
}

/// A hash of some bytes as a `Cid` for a blob.
pub fn blob_cid(bytes: &[u8]) -> Cid {
    Cid(format!("fakecid_{}", fake_hex(bytes)))
}

/// Hash helper for anything `Hash`.
pub fn hash_of<T: Hash>(t: &T) -> u64 {
    struct Fnv(u64);
    impl Hasher for Fnv {
        fn finish(&self) -> u64 {
            self.0
        }
        fn write(&mut self, bytes: &[u8]) {
            for b in bytes {
                self.0 ^= u64::from(*b);
                self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
            }
        }
    }
    let mut h = Fnv(0xcbf2_9ce4_8422_2325);
    t.hash(&mut h);
    h.finish()
}
