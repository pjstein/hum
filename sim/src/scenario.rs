//! Scenarios: what the simulator runs. `fast_suite` is the per-commit set,
//! `full_suite` the nightly set. Each scenario runs in its own world and
//! returns a `ScenarioResult` for the report.

use std::path::PathBuf;
use std::time::Instant;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use serde::Serialize;

use crate::data::VoteMatrix;
use crate::data::polis;
use crate::data::synthetic::{SyntheticSpec, generate};
use crate::fakes::Tiering;
use crate::leak::LeakReport;
use crate::pipeline::accounting::{DELTA, eps_to_rho};
use crate::pipeline::baseline::baseline;
use crate::pipeline::compare::{Metrics, churn, compare};
use crate::pipeline::dp::{DpParams, dp_pipeline};
use crate::ports::{Ballot, Floors, Ledger, Manifest};
use crate::thresholds::{self, GateResult, ReferenceRow, SourceKind};
use crate::world::{World, research_plan};

/// Where a scenario's votes come from.
#[derive(Clone, Debug, Serialize)]
pub enum Source {
    /// The seeded synthetic fixture.
    Synthetic {
        /// Generator seed.
        seed: u64,
    },
    /// One Polis conversation directory.
    Polis {
        /// Root of the open data checkout.
        root: PathBuf,
        /// Conversation directory name.
        conversation: String,
    },
}

impl Source {
    /// Source kind for the gate table.
    pub fn kind(&self) -> SourceKind {
        match self {
            Source::Synthetic { .. } => SourceKind::Synthetic,
            Source::Polis { .. } => SourceKind::Polis,
        }
    }

    /// Load the full matrix.
    pub fn load(&self, at_least: usize) -> anyhow::Result<VoteMatrix> {
        match self {
            Source::Synthetic { seed } => Ok(generate(&SyntheticSpec::sized(at_least), *seed)),
            Source::Polis { root, conversation } => polis::load(&root.join(conversation)),
        }
    }
}

/// What a scenario does.
#[derive(Clone, Debug, Serialize)]
pub enum Kind {
    /// Replay a conversation at a size and ε through the world (ε ≤ 4) or
    /// through the pipeline alone (above the protocol floor).
    PolisReplay {
        /// Participants.
        size: usize,
        /// ε per release.
        eps: f64,
        /// Noise seeds.
        seeds: Vec<u64>,
    },
    /// Chat → map → deck → vote → release → digest, with a shared agent.
    FullRatchet {
        /// Members.
        size: usize,
    },
    /// During one deck members restore from a backup after voting (hand lost,
    /// shield rebuilt as an upper bound, ballot counted once), do not vote, or
    /// join late; a second deck with dropouts. (Leaving a context and
    /// post-close round dropouts are not modelled until W1-03 and W1-05 land.)
    Churn {
        /// Members at the start.
        size: usize,
    },
    /// A deck that closes below the voter minimum: the release is logged
    /// with nothing unlocked (`release.md` R6).
    BelowMinimum {
        /// Members.
        size: usize,
    },
    /// A wave 2 adversarial hook with its wave 0 minimal check.
    Adversarial {
        /// Which hook.
        hook: Adversary,
    },
}

/// Adversarial hooks. Wave 2 fills these in; wave 0 wires the switch and the
/// detection each one must trigger.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Adversary {
    /// A ledger that rewrites an entry after appending it.
    LyingLedger,
    /// A client that ignores its floors.
    ModifiedClient,
    /// A verifier that asks for more than its manifest declares.
    OverCollectingVerifier,
    /// A shared agent that tries to vote.
    MaliciousAgent,
}

/// All hooks, in report order.
pub const ADVERSARIES: [Adversary; 4] = [
    Adversary::LyingLedger,
    Adversary::ModifiedClient,
    Adversary::OverCollectingVerifier,
    Adversary::MaliciousAgent,
];

/// One scenario.
#[derive(Clone, Debug, Serialize)]
pub struct Scenario {
    /// Name in reports.
    pub name: String,
    /// Source.
    pub source: Source,
    /// Kind.
    pub kind: Kind,
}

/// Status of a scenario in a report.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
pub enum Status {
    /// Everything passed.
    Pass,
    /// A gate, an oracle or the leak checker failed.
    Fail,
    /// Wave 1 or 2 fills this in, the pair has no gate, or the source was too small.
    Pending,
}

/// A leak report's summary for the JSON report.
#[derive(Clone, Debug, Serialize)]
pub struct LeakSummary {
    /// Records scanned.
    pub records: usize,
    /// Records per service.
    pub records_by_service: std::collections::BTreeMap<String, usize>,
    /// Calls per port.
    pub calls_by_service: std::collections::BTreeMap<String, usize>,
    /// Secrets registered.
    pub secrets: usize,
    /// Violations.
    pub violations: Vec<crate::leak::Violation>,
}

impl From<LeakReport> for LeakSummary {
    fn from(r: LeakReport) -> Self {
        Self {
            records: r.records,
            records_by_service: r.records_by_service,
            calls_by_service: r.calls_by_service,
            secrets: r.secrets,
            violations: r.violations,
        }
    }
}

fn merge(leaks: Vec<LeakReport>) -> LeakSummary {
    let mut out = LeakSummary {
        records: 0,
        records_by_service: std::collections::BTreeMap::default(),
        calls_by_service: std::collections::BTreeMap::default(),
        secrets: 0,
        violations: vec![],
    };
    for l in leaks {
        out.records += l.records;
        out.secrets += l.secrets;
        for (k, v) in l.records_by_service {
            *out.records_by_service.entry(k).or_insert(0) += v;
        }
        for (k, v) in l.calls_by_service {
            *out.calls_by_service.entry(k).or_insert(0) += v;
        }
        out.violations.extend(l.violations);
    }
    out.violations.sort();
    out.violations.dedup();
    out
}

/// What a scenario produced.
#[derive(Clone, Debug, Serialize)]
pub struct ScenarioResult {
    /// Name.
    pub name: String,
    /// Kind label.
    pub kind: String,
    /// Source label.
    pub source: String,
    /// Participants.
    pub size: usize,
    /// Statements.
    pub statements: usize,
    /// ε, for replays.
    pub eps: Option<f64>,
    /// Seeds run.
    pub seeds: Vec<u64>,
    /// Whether ballots went through phones and services (false above the floor).
    pub through_world: bool,
    /// Metrics per seed.
    pub per_seed: Vec<Metrics>,
    /// Mean metrics.
    pub mean: Option<Metrics>,
    /// The no-DP churn floor at this size.
    pub churn: Option<Metrics>,
    /// Research rows to compare with.
    pub reference: Vec<ReferenceRow>,
    /// Gate outcomes.
    pub gates: Vec<GateResult>,
    /// Protocol violations.
    pub protocol_violations: Vec<String>,
    /// Leak check.
    pub leak: Option<LeakSummary>,
    /// Notes for the reader.
    pub notes: Vec<String>,
    /// Status.
    pub status: Status,
    /// Wall time.
    pub seconds: f64,
}

impl ScenarioResult {
    fn blank(s: &Scenario) -> Self {
        Self {
            name: s.name.clone(),
            kind: match &s.kind {
                Kind::PolisReplay { .. } => "polis-replay".into(),
                Kind::FullRatchet { .. } => "full-ratchet".into(),
                Kind::Churn { .. } => "churn".into(),
                Kind::BelowMinimum { .. } => "below-minimum".into(),
                Kind::Adversarial { hook } => format!("adversarial/{hook:?}"),
            },
            source: match &s.source {
                Source::Synthetic { seed } => format!("synthetic(seed {seed})"),
                Source::Polis { conversation, .. } => format!("polis/{conversation}"),
            },
            size: 0,
            statements: 0,
            eps: None,
            seeds: vec![],
            through_world: true,
            per_seed: vec![],
            mean: None,
            churn: None,
            reference: vec![],
            gates: vec![],
            protocol_violations: vec![],
            leak: None,
            notes: vec![],
            status: Status::Pass,
            seconds: 0.0,
        }
    }

    fn finish(&mut self, started: Instant) {
        self.seconds = started.elapsed().as_secs_f64();
        let gates_ok = self.gates.iter().all(|g| g.pass);
        let leak_ok = self
            .leak
            .as_ref()
            .is_none_or(|l| l.records > 0 && l.violations.is_empty());
        if !(gates_ok && leak_ok && self.protocol_violations.is_empty()) {
            self.status = Status::Fail;
        }
    }
}

/// The per-commit suite: synthetic replays at 300 and 800 at ε 4, the full
/// ratchet, churn, a below-minimum deck and the adversarial hooks.
pub fn fast_suite() -> Vec<Scenario> {
    let syn = Source::Synthetic { seed: 1 };
    let mut v = vec![];
    for size in [300usize, 800] {
        v.push(Scenario {
            name: format!("replay-{size}-eps4"),
            source: syn.clone(),
            kind: Kind::PolisReplay {
                size,
                eps: 4.0,
                seeds: vec![0, 1],
            },
        });
    }
    v.push(Scenario {
        name: "full-ratchet-300".into(),
        source: syn.clone(),
        kind: Kind::FullRatchet { size: 300 },
    });
    v.push(Scenario {
        name: "churn-300".into(),
        source: syn.clone(),
        kind: Kind::Churn { size: 300 },
    });
    v.push(Scenario {
        name: "below-minimum-40".into(),
        source: syn.clone(),
        kind: Kind::BelowMinimum { size: 40 },
    });
    for hook in ADVERSARIES {
        v.push(Scenario {
            name: format!("adversarial-{hook:?}"),
            source: syn.clone(),
            kind: Kind::Adversarial { hook },
        });
    }
    v
}

/// The nightly suite: every size and ε on the fixture, and on the four
/// research conversations when a Polis checkout is given. ε 1 is left out:
/// the research's size sweep has no ε 1 rows, so nothing could gate it.
pub fn full_suite(polis: Option<PathBuf>) -> Vec<Scenario> {
    let mut v = vec![];
    let sizes = [100usize, 300, 800, 1600, 5000];
    let epss = [2.0, 4.0, 8.0, 16.0];
    let seeds: Vec<u64> = (0..5).collect();
    for seed in [1u64, 2] {
        let syn = Source::Synthetic { seed };
        for &size in &sizes {
            for &eps in &epss {
                v.push(Scenario {
                    name: format!("replay-synthetic{seed}-{size}-eps{eps}"),
                    source: syn.clone(),
                    kind: Kind::PolisReplay {
                        size,
                        eps,
                        seeds: seeds.clone(),
                    },
                });
            }
        }
        v.push(Scenario {
            name: format!("full-ratchet-{seed}-1000"),
            source: syn.clone(),
            kind: Kind::FullRatchet { size: 1000 },
        });
        v.push(Scenario {
            name: format!("churn-{seed}-1000"),
            source: syn.clone(),
            kind: Kind::Churn { size: 1000 },
        });
        v.push(Scenario {
            name: format!("below-minimum-{seed}-40"),
            source: syn.clone(),
            kind: Kind::BelowMinimum { size: 40 },
        });
    }
    if let Some(root) = polis {
        for conv in polis::E2_SOURCES {
            let src = Source::Polis {
                root: root.clone(),
                conversation: conv.to_string(),
            };
            for &size in &sizes {
                for &eps in &epss {
                    v.push(Scenario {
                        name: format!("replay-{conv}-{size}-eps{eps}"),
                        source: src.clone(),
                        kind: Kind::PolisReplay {
                            size,
                            eps,
                            seeds: seeds.clone(),
                        },
                    });
                }
            }
        }
    }
    for hook in ADVERSARIES {
        v.push(Scenario {
            name: format!("adversarial-{hook:?}"),
            source: Source::Synthetic { seed: 1 },
            kind: Kind::Adversarial { hook },
        });
    }
    v
}

/// Run one scenario.
pub fn run(s: &Scenario) -> ScenarioResult {
    let started = Instant::now();
    let mut r = ScenarioResult::blank(s);
    let outcome = match &s.kind {
        Kind::PolisReplay { size, eps, seeds } => run_replay(s, *size, *eps, seeds, &mut r),
        Kind::FullRatchet { size } => run_full_ratchet(s, *size, &mut r),
        Kind::Churn { size } => run_churn(s, *size, &mut r),
        Kind::BelowMinimum { size } => run_below_minimum(s, *size, &mut r),
        Kind::Adversarial { hook } => run_adversarial(s, *hook, &mut r),
    };
    if let Err(e) = outcome {
        r.protocol_violations.push(format!("scenario error: {e:#}"));
    }
    r.finish(started);
    r
}

/// Load and size a conversation. Synthetic sources are generated at the size;
/// Polis sources are subsampled, or skipped when the conversation is too small.
fn sized_matrix(
    s: &Scenario,
    size: usize,
    rng: &mut impl Rng,
) -> anyhow::Result<Option<VoteMatrix>> {
    let full = s.source.load(size)?;
    if full.n() < size {
        return Ok(None);
    }
    if full.n() == size {
        return Ok(Some(full));
    }
    // The research subsampled only when n <= 0.85 × the conversation.
    if matches!(s.source, Source::Polis { .. }) && (size as f64) > 0.85 * full.n() as f64 {
        return Ok(None);
    }
    Ok(Some(full.subsample(size, rng)))
}

fn run_replay(
    s: &Scenario,
    size: usize,
    eps: f64,
    seeds: &[u64],
    r: &mut ScenarioResult,
) -> anyhow::Result<()> {
    r.size = size;
    r.eps = Some(eps);
    r.seeds = seeds.to_vec();
    r.reference = thresholds::reference_for(size, eps);
    let Some(gates) = thresholds::gates_for(s.source.kind(), size, eps) else {
        r.notes.push(format!(
            "no gate for {} at {size} voters, ε {eps}: not run",
            r.source
        ));
        r.status = Status::Pending;
        return Ok(());
    };
    let mut rng = ChaCha8Rng::seed_from_u64(10_000 + seeds.first().copied().unwrap_or(0));
    let Some(m) = sized_matrix(s, size, &mut rng)? else {
        r.notes.push(format!(
            "source has fewer than {size} participants; skipped"
        ));
        r.status = Status::Pending;
        return Ok(());
    };
    r.statements = m.c();
    let base = baseline(&m, &mut ChaCha8Rng::seed_from_u64(0));
    r.churn = Some(churn(&m, &base, 0.9, &mut ChaCha8Rng::seed_from_u64(500)));
    let rho = eps_to_rho(eps, DELTA);
    let through_world = rho <= Floors::protocol().max_rho + 1e-12;
    r.through_world = through_world;
    if !through_world {
        r.notes.push(format!(
            "ε {eps} is above the protocol floor (ε 4): pipeline only, no phones or services"
        ));
    }
    let mut per_seed = vec![];
    let mut leaks: Vec<LeakReport> = vec![];
    for &seed in seeds {
        if through_world {
            let mut w = World::new(seed, Tiering::Research);
            let phones = w.enroll(m.n());
            let ctx = w.create_context("replay", Floors::protocol());
            for &p in &phones {
                w.join(p, &ctx)?;
            }
            let statements: Vec<String> = (0..m.c()).map(|j| format!("card {j}")).collect();
            let deck = w.deal(
                &ctx,
                &format!("replay of {}", m.name),
                statements,
                &research_plan(rho, m.c()),
            )?;
            for (i, &p) in phones.iter().enumerate() {
                w.vote(&deck, p, m.row(i).to_vec())?;
            }
            let release = w.close(&deck, 1000 + seed)?;
            let (counted, rows) = w.counted_matrix(&deck);
            debug_assert_eq!(counted.n(), m.n());
            let mut dp = w.aggregator.last_analysis.clone().expect("closed");
            // Compare on the aggregator's row order using phone-side groups.
            if let Some(axes) = release.axes.as_ref() {
                dp.groups = rows
                    .iter()
                    .map(|&i| w.phones[i].locate(&deck, axes).map_or(0, |(_, g)| g))
                    .collect();
            }
            let base_rows: Vec<usize> = rows.iter().map(|&i| base.groups[i]).collect();
            per_seed.push(compare(&base, &dp, Some(&base_rows)));
            r.protocol_violations.extend(w.protocol_checks());
            leaks.push(w.leak_report());
        } else {
            let dp = dp_pipeline(
                &m,
                eps,
                &DpParams::default(),
                &mut ChaCha8Rng::seed_from_u64(1000 + seed),
            );
            per_seed.push(compare(&base, &dp, None));
        }
    }
    let mean = Metrics::mean(&per_seed);
    r.gates = thresholds::apply(gates, &mean);
    r.per_seed = per_seed;
    r.mean = Some(mean);
    if through_world {
        r.leak = Some(merge(leaks));
    }
    Ok(())
}

fn hands_for(m: &VoteMatrix, n: usize) -> Vec<Vec<Option<crate::data::Vote>>> {
    (0..n).map(|i| m.row(i % m.n()).to_vec()).collect()
}

fn run_full_ratchet(s: &Scenario, size: usize, r: &mut ScenarioResult) -> anyhow::Result<()> {
    r.size = size;
    let mut rng = ChaCha8Rng::seed_from_u64(77);
    let m = sized_matrix(s, size, &mut rng)?.ok_or_else(|| anyhow::anyhow!("source too small"))?;
    let mut w = World::new(size as u64, Tiering::Gated);
    let phones = w.enroll(size);
    let ctx = w.create_context("tenants", Floors::protocol());
    for &p in &phones {
        w.join(p, &ctx)?;
    }
    w.add_agent(&ctx, "facilitator");
    // Chat: a few members talk; one attaches a sealed file.
    let mut promoted = vec![];
    for (k, &p) in phones.iter().take(12).enumerate() {
        let attachment = if k == 3 {
            Some("photo of the broken boiler")
        } else {
            None
        };
        let id = w.post(
            &ctx,
            p,
            &format!("message {k} about ignored repair requests"),
            attachment,
        );
        if k % 4 == 0 {
            promoted.push(w.promote(&ctx, id, "Ignored repair requests: what do we do?"));
        }
    }
    r.notes.push(format!(
        "{} messages, {} promoted to positions, 1 sealed attachment",
        w.messages.len(),
        promoted.len()
    ));
    // Deal a deck of the promoted positions plus synthetic cards up to 20.
    let cards = 20.min(m.c());
    r.statements = cards;
    let statements: Vec<String> = (0..cards).map(|j| format!("position {j}")).collect();
    let deck = w.deal(
        &ctx,
        "Fall check-in",
        statements,
        &research_plan(0.254, cards),
    )?;
    let hands = hands_for(&m, size);
    let mut cast = 0;
    for (i, &p) in phones.iter().enumerate() {
        let hand: Vec<_> = hands[i][..cards].to_vec();
        if hand.iter().any(Option::is_some) {
            w.vote(&deck, p, hand)?;
            cast += 1;
        }
    }
    // The agent tries to vote: it has no card, so no presentation verifies.
    let agent_ballot = Ballot {
        deck: deck.clone(),
        pseudonym: "vp_a9e47a9e47a9e47a".into(),
        presentation: "zk_0000000000000000".into(),
        votes: vec![None; cards],
    };
    match w.submit_raw(&agent_ballot) {
        Err(e) => w
            .expected_refusals
            .push(format!("agent ballot refused: {e}")),
        Ok(_) => r
            .protocol_violations
            .push("aggregator accepted a ballot from an agent".into()),
    }
    let release = w.close(&deck, 5)?;
    r.notes.push(format!(
        "{cast} ballots, released parts {:?}, n̂ {:?}",
        release.parts,
        release.n_hat.map(f64::round)
    ));
    let digest_by_agent = w
        .messages
        .last()
        .is_some_and(|msg| msg.author.starts_with("[agent]"));
    if !digest_by_agent {
        r.protocol_violations
            .push("digest was not posted by the labeled agent".into());
    }
    let events = &w.delivery.channels[&w.contexts[&ctx].channel].events;
    if !events.iter().any(|e| e.contains("agent:facilitator")) {
        r.protocol_violations
            .push("adding the agent was not a visible membership event".into());
    }
    r.protocol_violations.extend(w.protocol_checks());
    r.notes.extend(w.expected_refusals.iter().cloned());
    // The forged agent token is on the tape by design; the checker must flag it and nothing else.
    let mut leak = w.leak_report();
    let forged: Vec<_> = leak
        .violations
        .iter()
        .filter(|v| v.rule == "unknown-identity-token")
        .cloned()
        .collect();
    if forged.is_empty() {
        r.protocol_violations
            .push("leak checker did not flag the agent's forged pseudonym".into());
    }
    leak.violations
        .retain(|v| v.rule != "unknown-identity-token");
    r.leak = Some(leak.into());
    Ok(())
}

fn run_churn(s: &Scenario, size: usize, r: &mut ScenarioResult) -> anyhow::Result<()> {
    r.size = size;
    let mut rng = ChaCha8Rng::seed_from_u64(78);
    let late = size / 10;
    let m = sized_matrix(s, size + late, &mut rng)?
        .ok_or_else(|| anyhow::anyhow!("source too small"))?;
    let cards = m.c();
    r.statements = cards;
    let mut w = World::new(size as u64 + 1, Tiering::Research);
    let phones = w.enroll(size + late);
    let ctx = w.create_context("churn", Floors::protocol());
    for &p in &phones[..size] {
        w.join(p, &ctx)?;
    }
    let statements: Vec<String> = (0..cards).map(|j| format!("card {j}")).collect();
    let plan = research_plan(0.254, cards);
    let deck = w.deal(&ctx, "deck 1", statements.clone(), &plan)?;
    let hands = hands_for(&m, size + late);
    // First 70% vote.
    let first = size * 7 / 10;
    for &p in &phones[..first] {
        w.vote(&deck, p, hands[p].clone())?;
    }
    // 10% of those restore from a backup onto a new device: the hand is lost,
    // the shield is rebuilt as an upper bound, the counted ballot stands, and
    // a re-vote derives the same nullifier so it replaces rather than adds.
    let restored: Vec<usize> = phones[..first / 10].to_vec();
    for &p in &restored {
        w.restore(p);
        w.vote(&deck, p, hands[p].clone())?;
    }
    // 10% never vote; late joiners arrive and vote.
    let silent = &phones[first..first + size / 10];
    r.notes.push(format!(
        "{} restored from backup after voting and re-voted, {} did not vote, {late} joined late",
        restored.len(),
        silent.len()
    ));
    for &p in &phones[size..] {
        w.join(p, &ctx)?;
        w.vote(&deck, p, hands[p].clone())?;
    }
    for &p in &phones[first + size / 10..size] {
        w.vote(&deck, p, hands[p].clone())?;
    }
    let expected_ballots = first + late + (size - first - size / 10);
    if w.aggregator.ballots(&deck) != expected_ballots {
        r.protocol_violations.push(format!(
            "expected {expected_ballots} ballots, aggregator holds {}",
            w.aggregator.ballots(&deck)
        ));
    }
    for &p in &restored {
        let e: Vec<_> = w.phones[p]
            .shield
            .entries
            .iter()
            .filter(|e| e.deck == deck)
            .collect();
        if e.len() != 1 {
            r.protocol_violations.push(format!(
                "restored phone {p} has {} shield entries for deck 1",
                e.len()
            ));
        }
    }
    let release = w.close(&deck, 9)?;
    r.notes.push(format!(
        "deck 1: {expected_ballots} ballots, n̂ {:?}",
        release.n_hat.map(f64::round)
    ));
    // A second deck: 20% drop out between releases; shields accumulate.
    let deck2 = w.deal(&ctx, "deck 2", statements, &plan)?;
    let mut voted2 = 0;
    for (k, &p) in phones.iter().enumerate() {
        if k % 5 == 0 || !w.contexts[&ctx].members.contains(&p) {
            continue;
        }
        w.vote(&deck2, p, hands[p].clone())?;
        voted2 += 1;
    }
    let release2 = w.close(&deck2, 10)?;
    r.notes.push(format!(
        "deck 2: {voted2} ballots, n̂ {:?}",
        release2.n_hat.map(f64::round)
    ));
    let two = w
        .phones
        .iter()
        .filter(|p| p.shield.entries.len() == 2)
        .count();
    if !w
        .phones
        .iter()
        .filter(|p| p.shield.entries.len() == 2)
        .all(|p| (p.shield.spent_rho() - 0.508).abs() < 1e-9)
    {
        r.protocol_violations
            .push("a phone with two decks on its shield did not count exactly 2 × 0.254".into());
    }
    r.notes
        .push(format!("{two} phones carry two decks on their shield"));
    r.protocol_violations.extend(w.protocol_checks());
    r.leak = Some(w.leak_report().into());
    Ok(())
}

fn run_below_minimum(s: &Scenario, size: usize, r: &mut ScenarioResult) -> anyhow::Result<()> {
    r.size = size;
    let mut rng = ChaCha8Rng::seed_from_u64(80);
    let m = sized_matrix(s, size, &mut rng)?.ok_or_else(|| anyhow::anyhow!("source too small"))?;
    r.statements = m.c();
    let mut w = World::new(size as u64 + 3, Tiering::Gated);
    let phones = w.enroll(size);
    let ctx = w.create_context("small", Floors::protocol());
    for &p in &phones {
        w.join(p, &ctx)?;
    }
    let deck = w.deal(
        &ctx,
        "too small",
        (0..m.c()).map(|j| format!("card {j}")).collect(),
        &research_plan(0.254, m.c()),
    )?;
    for (i, &p) in phones.iter().enumerate() {
        w.vote(&deck, p, m.row(i).to_vec())?;
    }
    let release = w.close(&deck, 11)?;
    match release.n_hat {
        None => {
            if !release.parts.is_empty() || !release.tallies.is_empty() {
                r.protocol_violations
                    .push("a below-minimum release published tables".into());
            }
            r.notes.push(format!(
                "closed below the minimum: logged with nothing unlocked, ρ spent {:.4}",
                release.rho
            ));
        }
        Some(n) => {
            r.notes.push(format!(
                "noise lifted n̂ to {n:.0}: the below-minimum path was not exercised this seed"
            ));
            r.status = Status::Pending;
        }
    }
    if w.ledger.entries.len() != 1 {
        r.protocol_violations.push(format!(
            "ledger has {} entries, expected 1",
            w.ledger.entries.len()
        ));
    }
    r.protocol_violations.extend(w.protocol_checks());
    r.leak = Some(w.leak_report().into());
    Ok(())
}

fn run_adversarial(s: &Scenario, hook: Adversary, r: &mut ScenarioResult) -> anyhow::Result<()> {
    let size = 120;
    r.size = size;
    let mut rng = ChaCha8Rng::seed_from_u64(79);
    let m = sized_matrix(s, size, &mut rng)?.ok_or_else(|| anyhow::anyhow!("source too small"))?;
    let cards = m.c();
    r.statements = cards;
    let mut w = World::new(900 + size as u64, Tiering::Research);
    let detected: Result<String, String> = match hook {
        Adversary::OverCollectingVerifier => {
            w.issuer.over_collects = true;
            let phones = w.enroll(size);
            let carded = phones
                .iter()
                .filter(|&&p| w.phones[p].resident_card.is_some())
                .count();
            if carded == 0 && w.issuer.issued == 0 {
                Ok(format!(
                    "{size} phones refused to apply to the over-collecting verifier (the world refuses; nothing is tested yet)"
                ))
            } else {
                Err("some phones applied to an over-collecting verifier".into())
            }
        }
        Adversary::LyingLedger => {
            let phones = w.enroll(size);
            let ctx = w.create_context("adversarial", Floors::protocol());
            for &p in &phones {
                w.join(p, &ctx)?;
            }
            let deck = w.deal(
                &ctx,
                "deck",
                (0..cards).map(|j| format!("card {j}")).collect(),
                &research_plan(0.254, cards),
            )?;
            for (i, &p) in phones.iter().enumerate() {
                w.vote(&deck, p, m.row(i).to_vec())?;
            }
            w.ledger.lying = true;
            w.close(&deck, 3)?;
            match w.ledger.verify() {
                Err(e) => Ok(format!("ledger rewrite detected: {e}")),
                Ok(_) => Err("a rewritten ledger entry verified".into()),
            }
        }
        Adversary::ModifiedClient => {
            let phones = w.enroll(size);
            let ctx = w.create_context("adversarial", Floors::protocol());
            for &p in &phones {
                w.join(p, &ctx)?;
                w.phones[p].modified = true;
            }
            // A modified client accepts a plan above the floor; honest services must not.
            let plan = research_plan(0.6, cards);
            let phone_ok = w.phones[phones[0]].check_deck(
                &Manifest {
                    kind: "deck".into(),
                    authority: "x".into(),
                    version: 1,
                    prev: None,
                    refs: [("context".to_string(), ctx.clone())].into_iter().collect(),
                    body: serde_json::json!({ "plan": plan }),
                },
                &Floors::protocol(),
            );
            match (
                phone_ok,
                w.deal(
                    &ctx,
                    "loose deck",
                    (0..cards).map(|j| format!("card {j}")).collect(),
                    &plan,
                ),
            ) {
                (Ok(_), Err(e)) => Ok(format!(
                    "modified client accepted the plan; aggregator refused: {e}"
                )),
                (_, Ok(_)) => Err("aggregator opened a deck above the floor".into()),
                (Err(e), _) => Err(format!(
                    "modified-client hook did not bypass the phone check: {e}"
                )),
            }
        }
        Adversary::MaliciousAgent => {
            let phones = w.enroll(size);
            let ctx = w.create_context("adversarial", Floors::protocol());
            for &p in &phones {
                w.join(p, &ctx)?;
            }
            w.add_agent(&ctx, "sneaky");
            let deck = w.deal(
                &ctx,
                "deck",
                (0..cards).map(|j| format!("card {j}")).collect(),
                &research_plan(0.254, cards),
            )?;
            // The agent forges a pseudonym-shaped token with no card behind it,
            // then replays a real member's nullifier with its own presentation.
            let forged = Ballot {
                deck: deck.clone(),
                pseudonym: "vp_deadbeefdeadbeef".into(),
                presentation: "zk_deadbeefdeadbeef".into(),
                votes: vec![None; cards],
            };
            let victim = w.phones[phones[0]].pseudonym_for(&deck)?;
            let replay = Ballot {
                deck: deck.clone(),
                pseudonym: victim,
                presentation: "zk_deadbeefdeadbeef".into(),
                votes: vec![None; cards],
            };
            let forged_refused = w.submit_raw(&forged).is_err();
            let replay_refused = w.submit_raw(&replay).is_err();
            let flagged = w
                .leak_report()
                .violations
                .iter()
                .any(|v| v.rule == "unknown-identity-token");
            if forged_refused && replay_refused && flagged && w.aggregator.ballots(&deck) == 0 {
                Ok("forged and replayed ballots refused by the aggregator; forged token flagged by the leak checker".into())
            } else {
                Err(format!(
                    "forged refused {forged_refused}, replay refused {replay_refused}, flagged {flagged}"
                ))
            }
        }
    };
    match detected {
        Ok(note) => r.notes.push(note),
        Err(e) => r.protocol_violations.push(e),
    }
    r.notes
        .push("wave 0 minimal check; wave 2 fills the full attack".into());
    if r.protocol_violations.is_empty() {
        r.status = Status::Pending;
    }
    Ok(())
}
