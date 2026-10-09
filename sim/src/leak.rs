//! The leak checker: searches everything every service saw (the tape) for
//! anything it must never see. This is how invariants 1, 2 and 4 of
//! `CLAUDE.md` are tested continuously.
//!
//! Secrets are registered per phone in a [`Secrets`] registry by kind. The
//! checker scans every record's raw bytes for every registered value in raw,
//! lowercase-hex and base64url forms, so a real credential, nullifier or key
//! is found however a component serialises it. A second, weaker net looks
//! for the simulator's own field names (`votes`, `hand`, `shield`).
//!
//! The allow table [`ALLOWED`] is derived from `docs/design.md`'s who-sees-what
//! table, `services.md`'s logging table and ADR 0107, one row per service and
//! one entry per identity class. Everything not listed is forbidden. Two
//! kinds are scoped: a token-scope nullifier and an issuance nullifier are
//! allowed only at the one service named when they were registered.
//!
//! Vacuity: the world counts calls per port. A port that was called and has
//! no tape records fails the check, so a real component wired without its
//! recording wrapper fails the run instead of passing it silently.

use std::collections::{BTreeMap, HashMap};

use serde::Serialize;

use crate::ports::{SERVICES, Tape};

/// Kinds of secret the registry knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub enum Kind {
    /// The resident card (anonymous credential).
    ResidentCard,
    /// The per-deck voting pseudonym (nullifier).
    Pseudonym,
    /// The chat key, which also signs authored objects.
    ChatKey,
    /// A sealed-blob key.
    SealedKey,
    /// The canary seeded into a hand.
    HandCanary,
    /// A device key (an MLS leaf's credential). Never reaches any service.
    DeviceKey,
    /// An authored-object nullifier (`hum/author-once/1`, `hum/author-slot/1`).
    AuthorNullifier,
    /// A token-scope nullifier (`hum/blob-tokens/1`, `hum/delivery-tokens/1`):
    /// allowed only at the token issuer it was presented to, named at registration.
    TokenScopeNullifier,
    /// A join nullifier (`hum/join/1`): lives only inside MLS ciphertext.
    JoinNullifier,
    /// An issuance nullifier (`hum/issuance/1`): allowed only at the issuing
    /// host that asked for the card, named at registration.
    IssuanceNullifier,
    /// The public card fields (issuer, `kid`, `len`, epoch) as one tuple:
    /// allowed wherever a presentation is allowed; equal across a context (C16).
    PublicCardFields,
}

/// Which identity classes each service may see (`docs/specs/simulator.md`,
/// "The allow table"):
///
/// | Service | May see |
/// | --- | --- |
/// | aggregator | pseudonym (phase 1 sees pseudonymous ballots); public card fields |
/// | ledger (the log) | chat key as an author's signing key; author nullifiers; public card fields |
/// | delivery | public card fields (as a token issuer). Device keys never reach it: every handshake is a `PrivateMessage` and `KeyPackage`s are sealed blobs (`chat.md` §12.9) |
/// | issuer | public card fields |
/// | store | public card fields (as a token issuer) |
///
/// Resident cards, sealed keys, hand canaries, device keys and join nullifiers
/// are allowed nowhere. Token-scope and issuance nullifiers are allowed only at
/// the one service named when they were registered (ADR 0107).
pub const ALLOWED: &[(&str, &[Kind])] = &[
    ("aggregator", &[Kind::Pseudonym, Kind::PublicCardFields]),
    (
        "ledger",
        &[Kind::ChatKey, Kind::AuthorNullifier, Kind::PublicCardFields],
    ),
    ("delivery", &[Kind::PublicCardFields]),
    ("issuer", &[Kind::PublicCardFields]),
    ("store", &[Kind::PublicCardFields]),
];

/// Kinds that are allowed only at the service named at registration.
pub const SCOPED: &[Kind] = &[Kind::TokenScopeNullifier, Kind::IssuanceNullifier];

/// Pairs of kinds that may never share one record, even where each is
/// allowed on its own.
pub const NEVER_TOGETHER: &[(Kind, Kind)] = &[
    (Kind::AuthorNullifier, Kind::Pseudonym),
    (Kind::ChatKey, Kind::Pseudonym),
];

fn allowed(service: &str, kind: Kind) -> bool {
    ALLOWED
        .iter()
        .any(|(s, kinds)| *s == service && kinds.contains(&kind))
}

/// One registered secret in one form.
#[derive(Debug, Clone)]
struct Entry {
    phone: usize,
    kind: Kind,
    form: Vec<u8>,
    /// For scoped kinds: the one service allowed to see it.
    scope: Option<&'static str>,
}

/// Registered secrets, by phone and kind, in every form the scan looks for.
#[derive(Debug, Default)]
pub struct Secrets {
    entries: Vec<Entry>,
    /// First four bytes of each registered form → entry indices.
    index: HashMap<[u8; 4], Vec<usize>>,
    /// Public card fields per use (one deck's ballots, or one context
    /// version's join, token and authorship presentations), for C16.
    card_fields: Vec<CardFieldsUse>,
}

/// One presentation's public card fields, as registered for a use.
#[derive(Debug, Clone)]
struct CardFieldsUse {
    use_label: String,
    phone: usize,
    /// Issuer, `kid` and `len`, without the epoch.
    fields: Vec<u8>,
    epoch: u64,
    /// The use fell inside the grace window after an epoch turn, so two
    /// adjacent epochs are allowed in it.
    in_grace: bool,
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63]);
        out.push(B64[(n >> 12) as usize & 63]);
        if chunk.len() > 1 {
            out.push(B64[(n >> 6) as usize & 63]);
        }
        if chunk.len() > 2 {
            out.push(B64[n as usize & 63]);
        }
    }
    out
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect()
}

/// A hit: which phone's secret of which kind, and its scope if any.
type Hit = (usize, Kind, Option<&'static str>);

impl Secrets {
    /// Register one secret for a phone. Values shorter than 8 bytes are
    /// refused: they would match by accident. Scoped kinds must use
    /// [`Secrets::register_scoped`].
    pub fn register(&mut self, phone: usize, kind: Kind, value: &[u8]) {
        assert!(!SCOPED.contains(&kind), "{kind:?} needs register_scoped");
        self.push(phone, kind, value, None);
    }

    /// Register a token-scope or issuance nullifier, allowed only at `service`.
    pub fn register_scoped(
        &mut self,
        phone: usize,
        kind: Kind,
        value: &[u8],
        service: &'static str,
    ) {
        assert!(SCOPED.contains(&kind), "{kind:?} is not a scoped kind");
        self.push(phone, kind, value, Some(service));
    }

    /// Register a phone's public card fields tuple as presented in `context`.
    /// Every member of a context must register the same tuple (C16).
    /// Register a card-derived scope twice: the pseudonym a presentation
    /// carries and the nullifier that is its hash. Both get the same kind and
    /// the same allow rule, because a pseudonym that reached the wrong service
    /// would not be found by a scan for its nullifier.
    pub fn register_card_scope(
        &mut self,
        phone: usize,
        kind: Kind,
        pseudonym: &[u8],
        nullifier: &[u8],
    ) {
        assert!(
            !SCOPED.contains(&kind),
            "{kind:?} needs register_card_scope_at"
        );
        self.push(phone, kind, pseudonym, None);
        self.push(phone, kind, nullifier, None);
    }

    /// The scoped form of [`Secrets::register_card_scope`].
    pub fn register_card_scope_at(
        &mut self,
        phone: usize,
        kind: Kind,
        pseudonym: &[u8],
        nullifier: &[u8],
        service: &'static str,
    ) {
        assert!(SCOPED.contains(&kind), "{kind:?} is not a scoped kind");
        self.push(phone, kind, pseudonym, Some(service));
        self.push(phone, kind, nullifier, Some(service));
    }

    /// Register the public card fields one presentation shows, for one use:
    /// `use_label` is the deck CID for a ballot, or the context version CID
    /// for a join, token or authorship presentation. `fields` is issuer,
    /// `kid` and `len`; `epoch` the card's epoch; `in_grace` whether the use
    /// fell in the first hour after an epoch turn (two hours for a logged
    /// object), when two adjacent epochs may appear together (C16).
    pub fn register_card_fields(
        &mut self,
        phone: usize,
        use_label: &str,
        fields: &[u8],
        epoch: u64,
        in_grace: bool,
    ) {
        let tuple = format!("{}/epoch-{epoch}", String::from_utf8_lossy(fields));
        self.push(phone, Kind::PublicCardFields, tuple.as_bytes(), None);
        self.card_fields.push(CardFieldsUse {
            use_label: use_label.to_string(),
            phone,
            fields: fields.to_vec(),
            epoch,
            in_grace,
        });
    }

    fn push(&mut self, phone: usize, kind: Kind, value: &[u8], scope: Option<&'static str>) {
        assert!(
            value.len() >= 8,
            "a registered secret needs at least 8 bytes"
        );
        for form in [value.to_vec(), hex(value), base64url(value)] {
            let key: [u8; 4] = form[..4].try_into().expect("at least 4 bytes");
            self.entries.push(Entry {
                phone,
                kind,
                form,
                scope,
            });
            self.index
                .entry(key)
                .or_default()
                .push(self.entries.len() - 1);
        }
    }

    /// Registered values (all forms counted once per value).
    pub fn len(&self) -> usize {
        self.entries.len() / 3
    }

    /// True when nothing is registered.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Contexts whose members registered different public card field tuples.
    /// Uses whose presentations show different public card fields (C16):
    /// within one use every presentation shows the same issuer, `kid` and
    /// `len`, and one epoch, or two adjacent epochs when the use fell in the
    /// grace window after an epoch turn.
    fn card_field_mismatches(&self) -> Vec<String> {
        let mut by_use: BTreeMap<&str, Vec<&CardFieldsUse>> = BTreeMap::new();
        for u in &self.card_fields {
            by_use.entry(u.use_label.as_str()).or_default().push(u);
        }
        let mut out = vec![];
        for (label, uses) in by_use {
            let first = uses[0];
            if let Some(other) = uses.iter().find(|u| u.fields != first.fields) {
                out.push(format!(
                    "use {label}: phone {} and phone {} present different issuer, kid or len",
                    first.phone, other.phone
                ));
                continue;
            }
            let mut epochs: Vec<u64> = uses.iter().map(|u| u.epoch).collect();
            epochs.sort_unstable();
            epochs.dedup();
            let grace = uses.iter().any(|u| u.in_grace);
            let ok = match epochs.as_slice() {
                [_] => true,
                [a, b] => grace && b - a == 1,
                _ => false,
            };
            if !ok {
                out.push(format!(
                    "use {label}: epochs {epochs:?} in one use (grace window: {grace})"
                ));
            }
        }
        out
    }

    /// Every hit in `haystack`, deduplicated.
    fn find(&self, haystack: &[u8]) -> Vec<Hit> {
        let mut found: Vec<Hit> = vec![];
        if haystack.len() < 4 {
            return found;
        }
        for i in 0..=haystack.len() - 4 {
            let key: [u8; 4] = haystack[i..i + 4].try_into().expect("4 bytes");
            if let Some(cands) = self.index.get(&key) {
                for &c in cands {
                    let e = &self.entries[c];
                    let hit = (e.phone, e.kind, e.scope);
                    if haystack[i..].starts_with(&e.form) && !found.contains(&hit) {
                        found.push(hit);
                    }
                }
            }
        }
        found
    }
}

/// One rule violation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Violation {
    /// Which rule.
    pub rule: &'static str,
    /// Which service.
    pub service: String,
    /// Which operation.
    pub op: String,
    /// What was found.
    pub detail: String,
}

/// The result of a check.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LeakReport {
    /// Records scanned.
    pub records: usize,
    /// Records per service.
    pub records_by_service: BTreeMap<String, usize>,
    /// Calls per port, as the world counted them.
    pub calls_by_service: BTreeMap<String, usize>,
    /// Secrets registered.
    pub secrets: usize,
    /// Violations found, sorted.
    pub violations: Vec<Violation>,
}

impl LeakReport {
    /// Passed: records were scanned, every called port was taped, nothing was found.
    pub fn passed(&self) -> bool {
        self.records > 0 && self.violations.is_empty()
    }
}

/// Does the payload carry a JSON key `k`, directly or escaped once inside a string?
fn has_key(payload: &str, k: &str) -> bool {
    payload.contains(&format!("\"{k}\"")) || payload.contains(&format!("\\\"{k}\\\""))
}

/// The prefixes the simulator's own tokens use, for the unknown-token rule.
const IDENTITY_PREFIXES: [(&str, Kind); 4] = [
    ("rc_", Kind::ResidentCard),
    ("vp_", Kind::Pseudonym),
    ("cn_", Kind::ChatKey),
    ("an_", Kind::AuthorNullifier),
];

fn sim_tokens_in(payload: &str, prefix: &str) -> Vec<String> {
    let mut out = vec![];
    let mut start = 0;
    while let Some(pos) = payload[start..].find(prefix) {
        let at = start + pos;
        if let Some(tok) = payload.get(at..at + 19)
            && tok[3..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            out.push(tok.to_string());
        }
        start = at + prefix.len();
    }
    out
}

/// Run every rule over the tape. `calls` is the world's per-port call count.
pub fn check(tape: &Tape, secrets: &Secrets, calls: &BTreeMap<&'static str, usize>) -> LeakReport {
    let mut report = LeakReport {
        records: tape.records.len(),
        records_by_service: tape
            .count_by_service()
            .into_iter()
            .map(|(k, v)| (k.to_string(), v))
            .collect(),
        calls_by_service: calls.iter().map(|(k, v)| ((*k).to_string(), *v)).collect(),
        secrets: secrets.len(),
        violations: vec![],
    };
    // Vacuity per port.
    for s in SERVICES {
        let called = calls.get(s).copied().unwrap_or(0);
        let taped = report.records_by_service.get(s).copied().unwrap_or(0);
        if called > 0 && taped == 0 {
            report.violations.push(Violation {
                rule: "port-not-taped",
                service: s.to_string(),
                op: String::new(),
                detail: format!("{called} calls, 0 tape records"),
            });
        }
    }
    if secrets.is_empty() {
        report.violations.push(Violation {
            rule: "no-secrets-registered",
            service: String::new(),
            op: String::new(),
            detail: "the registry is empty; nothing could have been found".into(),
        });
    }
    // C16: one public-card-fields tuple per context.
    for detail in secrets.card_field_mismatches() {
        report.violations.push(Violation {
            rule: "card-fields-differ-in-context",
            service: String::new(),
            op: String::new(),
            detail,
        });
    }
    for r in &tape.records {
        let mut push = |rule: &'static str, detail: String| {
            report.violations.push(Violation {
                rule,
                service: r.service.to_string(),
                op: r.op.to_string(),
                detail,
            });
        };
        let p = &r.payload;
        // Weaker net: the simulator's own field names.
        let carries_votes = has_key(p, "votes") || has_key(p, "hand") || has_key(p, "hands");
        if carries_votes && !(r.service == "aggregator" && r.op == "submit") {
            push(
                "votes-outside-ballot",
                "record carries votes or a hand".into(),
            );
        }
        if has_key(p, "shield") || p.contains("spent_rho") {
            push("shield-left-phone", "record carries a shield".into());
        }
        // Registered secrets in any form.
        let found = secrets.find(&r.raw);
        let mut by_phone: HashMap<usize, Vec<Kind>> = HashMap::new();
        for (phone, kind, scope) in &found {
            let ok = match scope {
                Some(service) => *service == r.service,
                None => allowed(r.service, *kind),
            };
            if !ok {
                push(
                    "identity-not-allowed-here",
                    format!("{} saw a {kind:?}", r.service),
                );
            }
            let e = by_phone.entry(*phone).or_default();
            if !e.contains(kind) {
                e.push(*kind);
            }
        }
        let mut phones: Vec<_> = by_phone.into_iter().collect();
        phones.sort();
        for (phone, mut kinds) in phones {
            kinds.sort();
            // Public card fields are the same for everyone and identify nobody.
            kinds.retain(|k| *k != Kind::PublicCardFields);
            if kinds.len() > 1 {
                push(
                    "identities-joined",
                    format!("phone {phone}: {kinds:?} in one record"),
                );
            }
        }
        let kinds_in_record: Vec<Kind> = found.iter().map(|(_, k, _)| *k).collect();
        for (a, b) in NEVER_TOGETHER {
            if kinds_in_record.contains(a) && kinds_in_record.contains(b) {
                push(
                    "classes-never-together",
                    format!("{a:?} and {b:?} in one record"),
                );
            }
        }
        // Identity-shaped tokens that no phone owns (forgeries).
        for (prefix, kind) in IDENTITY_PREFIXES {
            for tok in sim_tokens_in(p, prefix) {
                if !found.iter().any(|(_, k, _)| *k == kind)
                    || secrets.find(tok.as_bytes()).is_empty()
                {
                    push(
                        "unknown-identity-token",
                        format!("{tok} is not any simulated phone's"),
                    );
                }
            }
        }
    }
    report.violations.sort();
    report.violations.dedup();
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Vote;
    use crate::ports::{Ballot, Cid};

    fn setup() -> (Secrets, String, String, String, String, String) {
        let mut s = Secrets::default();
        let rc = "rc_0123456789abcdef".to_string();
        let vp = "vp_fedcba9876543210".to_string();
        let cn = "cn_00112233445566aa".to_string();
        let sk = "sk_aabbccddeeff0011".to_string();
        let hc = "hc_99887766554433ff".to_string();
        s.register(0, Kind::ResidentCard, rc.as_bytes());
        s.register(0, Kind::Pseudonym, vp.as_bytes());
        s.register(0, Kind::ChatKey, cn.as_bytes());
        s.register(0, Kind::SealedKey, sk.as_bytes());
        s.register(0, Kind::HandCanary, hc.as_bytes());
        (s, rc, vp, cn, sk, hc)
    }

    fn calls(v: &[(&'static str, usize)]) -> BTreeMap<&'static str, usize> {
        v.iter().copied().collect()
    }

    fn rules(r: &LeakReport) -> Vec<&'static str> {
        r.violations.iter().map(|v| v.rule).collect()
    }

    fn ballot(vp: String) -> Ballot {
        Ballot {
            deck: Cid("fakecid_d".into()),
            pseudonym: vp,
            presentation: "zk_x".into(),
            votes: vec![Some(Vote::Agree)],
        }
    }

    #[test]
    fn empty_tape_does_not_pass() {
        let (s, ..) = setup();
        assert!(!check(&Tape::default(), &s, &calls(&[])).passed());
    }

    #[test]
    fn a_called_port_with_no_records_fails() {
        let (s, _, vp, ..) = setup();
        let mut t = Tape::default();
        t.see("aggregator", "submit", &ballot(vp));
        let r = check(&t, &s, &calls(&[("aggregator", 1), ("delivery", 3)]));
        assert_eq!(rules(&r), vec!["port-not-taped"], "{r:?}");
        assert!(check(&t, &s, &calls(&[("aggregator", 1)])).passed());
    }

    #[test]
    fn an_empty_registry_fails() {
        let mut t = Tape::default();
        t.see("ledger", "append", &"x");
        assert!(
            rules(&check(&t, &Secrets::default(), &calls(&[("ledger", 1)])))
                .contains(&"no-secrets-registered")
        );
    }

    #[test]
    fn votes_outside_a_ballot() {
        let (s, ..) = setup();
        let mut t = Tape::default();
        t.see("ledger", "append", &"{\"votes\": [1]}".to_string());
        assert!(rules(&check(&t, &s, &calls(&[("ledger", 1)]))).contains(&"votes-outside-ballot"));
    }

    #[test]
    fn a_shield_off_the_phone() {
        let (s, ..) = setup();
        let mut t = Tape::default();
        t.see(
            "store",
            "put",
            &serde_json::json!({ "shield": { "spent_rho": 0.2 } }),
        );
        assert!(rules(&check(&t, &s, &calls(&[("store", 1)]))).contains(&"shield-left-phone"));
    }

    #[test]
    fn identities_joined_in_one_record() {
        let (s, rc, vp, ..) = setup();
        let mut t = Tape::default();
        t.see("aggregator", "log", &format!("{vp} is {rc}"));
        let r = rules(&check(&t, &s, &calls(&[("aggregator", 1)])));
        assert!(
            r.contains(&"identities-joined") && r.contains(&"identity-not-allowed-here"),
            "{r:?}"
        );
    }

    #[test]
    fn identity_not_allowed_at_a_service() {
        let (s, _, vp, cn, ..) = setup();
        let mut t = Tape::default();
        t.see("delivery", "send", &cn);
        t.see("ledger", "append", &vp);
        let r = check(&t, &s, &calls(&[("delivery", 1), ("ledger", 1)]));
        assert_eq!(
            r.violations
                .iter()
                .filter(|v| v.rule == "identity-not-allowed-here")
                .count(),
            2,
            "{r:?}"
        );
    }

    #[test]
    fn a_sealed_key_and_a_canary_in_hex_or_base64_are_found() {
        let (s, _, _, _, sk, hc) = setup();
        let mut t = Tape::default();
        t.see_bytes("store", "put", &"blob", &hex(sk.as_bytes()));
        t.see_bytes("store", "put", &"blob", &base64url(hc.as_bytes()));
        let r = check(&t, &s, &calls(&[("store", 2)]));
        let details: Vec<&str> = r.violations.iter().map(|v| v.detail.as_str()).collect();
        assert!(
            details.iter().any(|d| d.contains("SealedKey"))
                && details.iter().any(|d| d.contains("HandCanary")),
            "{details:?}"
        );
    }

    #[test]
    fn classes_never_together() {
        let (mut s, _, vp, ..) = setup();
        let an = "an_1234123412341234";
        s.register(0, Kind::AuthorNullifier, an.as_bytes());
        let mut t = Tape::default();
        t.see("ledger", "add", &format!("{an} {vp}"));
        assert!(
            rules(&check(&t, &s, &calls(&[("ledger", 1)]))).contains(&"classes-never-together")
        );
    }

    #[test]
    fn an_unknown_identity_token_is_a_forgery() {
        let (s, ..) = setup();
        let mut t = Tape::default();
        t.see("aggregator", "submit", &"vp_deadbeefdeadbeef");
        assert!(
            rules(&check(&t, &s, &calls(&[("aggregator", 1)]))).contains(&"unknown-identity-token")
        );
    }

    #[test]
    fn a_device_key_at_delivery_is_not_allowed() {
        let (mut s, ..) = setup();
        let dk = "dk_7777666655554444";
        s.register(0, Kind::DeviceKey, dk.as_bytes());
        let mut t = Tape::default();
        t.see("delivery", "membership", &format!("join {dk}"));
        assert!(
            rules(&check(&t, &s, &calls(&[("delivery", 1)])))
                .contains(&"identity-not-allowed-here")
        );
    }

    #[test]
    fn a_token_scope_nullifier_is_allowed_only_where_it_was_presented() {
        let (mut s, ..) = setup();
        let tn = "tn_1212121212121212";
        s.register_scoped(0, Kind::TokenScopeNullifier, tn.as_bytes(), "store");
        let mut t = Tape::default();
        t.see("store", "token", &tn);
        assert!(check(&t, &s, &calls(&[("store", 1)])).passed());
        t.see("delivery", "token", &tn);
        assert!(
            rules(&check(&t, &s, &calls(&[("store", 1), ("delivery", 1)])))
                .contains(&"identity-not-allowed-here")
        );
    }

    #[test]
    fn a_join_nullifier_is_allowed_nowhere() {
        let (mut s, ..) = setup();
        let jn = "jn_3434343434343434";
        s.register(0, Kind::JoinNullifier, jn.as_bytes());
        let mut t = Tape::default();
        t.see("ledger", "add", &jn);
        assert!(
            rules(&check(&t, &s, &calls(&[("ledger", 1)]))).contains(&"identity-not-allowed-here")
        );
    }

    #[test]
    fn an_issuance_nullifier_is_allowed_only_at_the_asking_issuer() {
        let (mut s, ..) = setup();
        let inn = "in_5656565656565656";
        s.register_scoped(0, Kind::IssuanceNullifier, inn.as_bytes(), "issuer");
        let mut t = Tape::default();
        t.see("issuer", "issue", &inn);
        assert!(check(&t, &s, &calls(&[("issuer", 1)])).passed());
        t.see("aggregator", "submit", &inn);
        assert!(
            rules(&check(&t, &s, &calls(&[("issuer", 1), ("aggregator", 1)])))
                .contains(&"identity-not-allowed-here")
        );
    }

    #[test]
    fn public_card_fields_must_match_within_a_use() {
        let (mut s, ..) = setup();
        s.register_card_fields(0, "deck-a", b"issuer-fake/k1/32", 7, false);
        s.register_card_fields(1, "deck-a", b"issuer-fake/k1/32", 7, false);
        let mut t = Tape::default();
        t.see("aggregator", "submit", &"issuer-fake/k1/32/epoch-7");
        t.see("delivery", "token", &"issuer-fake/k1/32/epoch-7");
        assert!(check(&t, &s, &calls(&[("aggregator", 1), ("delivery", 1)])).passed());
        s.register_card_fields(2, "deck-a", b"issuer-fake/k2/32", 7, false);
        let r = check(&t, &s, &calls(&[("aggregator", 1), ("delivery", 1)]));
        assert!(
            rules(&r).contains(&"card-fields-differ-in-context"),
            "{r:?}"
        );
    }

    #[test]
    fn two_epochs_in_one_use_need_the_grace_window_and_adjacency() {
        let mut t = Tape::default();
        t.see("aggregator", "submit", &"x");
        let c = calls(&[("aggregator", 1)]);
        // Different uses may carry different epochs: a ballot's epoch is fixed
        // by its deck's version-1 closes.
        let (mut s, ..) = setup();
        s.register_card_fields(0, "deck-a", b"issuer-fake/k1/32", 7, false);
        s.register_card_fields(1, "deck-b", b"issuer-fake/k1/32", 8, false);
        assert!(check(&t, &s, &c).passed());
        // Adjacent epochs inside the grace window pass.
        s.register_card_fields(2, "deck-a", b"issuer-fake/k1/32", 8, true);
        assert!(check(&t, &s, &c).passed());
        // Outside the window they fail.
        let (mut s2, ..) = setup();
        s2.register_card_fields(0, "deck-c", b"issuer-fake/k1/32", 7, false);
        s2.register_card_fields(1, "deck-c", b"issuer-fake/k1/32", 8, false);
        assert!(rules(&check(&t, &s2, &c)).contains(&"card-fields-differ-in-context"));
        // Non-adjacent epochs fail even in the window.
        let (mut s3, ..) = setup();
        s3.register_card_fields(0, "deck-d", b"issuer-fake/k1/32", 7, true);
        s3.register_card_fields(1, "deck-d", b"issuer-fake/k1/32", 9, true);
        assert!(rules(&check(&t, &s3, &c)).contains(&"card-fields-differ-in-context"));
    }

    #[test]
    fn a_pseudonym_is_found_where_only_its_nullifier_was_known_before() {
        let mut s = Secrets::default();
        let pseudonym = "ps_abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let nullifier = "vp_0f0f0f0f0f0f0f0f";
        s.register_card_scope(
            0,
            Kind::Pseudonym,
            pseudonym.as_bytes(),
            nullifier.as_bytes(),
        );
        let mut t = Tape::default();
        t.see("aggregator", "submit", &pseudonym);
        assert!(check(&t, &s, &calls(&[("aggregator", 1)])).passed());
        t.see("ledger", "add", &pseudonym);
        assert!(
            rules(&check(&t, &s, &calls(&[("aggregator", 1), ("ledger", 1)])))
                .contains(&"identity-not-allowed-here")
        );
        // The scoped form behaves the same.
        let mut s2 = Secrets::default();
        s2.register_card_scope_at(
            0,
            Kind::TokenScopeNullifier,
            pseudonym.as_bytes(),
            nullifier.as_bytes(),
            "store",
        );
        let mut t2 = Tape::default();
        t2.see("delivery", "token", &pseudonym);
        assert!(
            rules(&check(&t2, &s2, &calls(&[("delivery", 1)])))
                .contains(&"identity-not-allowed-here")
        );
    }

    #[test]
    fn a_ballot_to_the_aggregator_is_fine() {
        let (s, _, vp, ..) = setup();
        let mut t = Tape::default();
        t.see("aggregator", "submit", &ballot(vp));
        let r = check(&t, &s, &calls(&[("aggregator", 1)]));
        assert!(r.passed(), "{r:?}");
    }
}
