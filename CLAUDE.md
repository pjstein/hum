# Hum

Hum is a chat app with superpowers for groups that need to decide things. Conversation in end-to-end encrypted channels ratchets into an issue map (issues, positions, pro and con arguments), positions are dealt as decks of cards that people vote on privately by swiping, and every deck ends in one differentially private release on a public ledger. Releases flow back into chat and into an open studio and gallery. No individual vote is ever attributable to anyone. Agents are first-class participants, and they never vote.

Hum is a stack of open protocols with one reference network and native iOS and Android apps. It launches on one network and is designed to federate.

## Read first

| Need | Read |
| --- | --- |
| What we're building and why | `docs/design.md` |
| The envelope every shared object uses | `docs/specs/manifest.md` |
| Other specs (written in wave 0) | `docs/specs/*.md` |
| What's decided, proposed and open | `docs/DECISIONS.md`, `docs/decisions/` |
| Screens and flows | `docs/ux/README.md`, `docs/ux/screens/` |
| DP math and its oracle | `docs/research/dp-polis/` |
| Living versions and standards | `docs/SOURCES.md` |
| The prompt for your task | `prompts/` |

The specs are normative. `docs/design.md` explains intent. When they disagree, the spec wins and you flag the disagreement.

## Invariants (never break these; stop and ask if a task seems to require it)

1. **No vote is attributable.** Votes leave a phone only as ballots to aggregators. Nothing else (chat, storage, logs, analytics, crash reports, agents) ever carries a vote, a hand or a shield.
2. **Three identities are never linked:** the resident card (anonymous credential), the per-context voting pseudonym, and the chat name. No code path, log line, cache key or metric may join two of them.
3. **Floors are enforced at the edges** (phone, aggregator, ledger) and can only get stricter. Draft 0.1 minimums: ρ ≤ 0.254 per release (ε 4 at δ 10⁻⁶), δ ≤ 10⁻⁶, at least 100 noised voters to publish, one release per deck, a declared contribution cap, a yearly shield of at most ε 20.
4. **Manifests carry no personal data,** and sealed-blob keys never appear in a manifest, a log, or a request to a store.
5. **Every release is a sum** of per-person contributions, so central DP can be replaced by two-server aggregation without changing the math.
6. **Nothing trusts a server for being the reference.** Clients accept only what's signed by the keys a manifest names and proven in a witnessed log. Manifests name services by key, never by hostname.
7. **Agents never vote,** their content is always labeled, and adding a shared agent to a channel is a visible membership event.
8. **Native only.** No web client, and no over-the-air code updates in the apps.

## How work flows

1. **Spec first.** Behavior is defined in `docs/specs/` before it's built. If a spec is ambiguous or wrong, don't guess in code: write the question in `docs/decisions/` (or the spec's open questions) and tell the owner.
2. **Vectors come from `reference/`** (the Python reference implementation), never from the code under test. Never hand-edit `vectors/`.
3. **Every change keeps the gates green:** formatting, lints, unit tests, the conformance suite against `vectors/`, and the fast simulator run. A change that's hard to put under the simulator is a design smell; say so.
4. **Stay in your lane.** Each workstream owns its directories (see its prompt). Needs in another workstream's area go in a short note in `docs/decisions/` or an issue, not a drive-by edit.
5. **Record decisions.** A library choice, a format detail a spec left open, or a deviation gets a short ADR in `docs/decisions/` and a line in `docs/DECISIONS.md`.

## Security seams (owner review required)

Code in these areas needs the owner's explicit review before merging. Mark the PR or summary with `seam:` and the area:

- signing, domain-separation strings, CID computation and canonical encoding
- key generation, storage and derivation; nonces; the sealed blob format; keyrings
- credential issuance and presentation, pseudonyms and nullifiers
- ballot construction, contribution caps, shield accounting
- DP noise sampling, budget accounting, release tiers and floor checks
- log proof verification and witness checks
- anything that decides what leaves the phone

Never hand-roll cryptography or noise sampling. Use the libraries recorded in `docs/DECISIONS.md`; adding a dependency in a seam needs approval. Floating-point noise sampling is a known attack surface: use a vetted discrete or exact sampler.

## Repo layout (created by the bootstrap prompt)

```
docs/        design, specs, ux, research, decisions — the source of truth
prompts/     the prompts that drive each wave
reference/   Python reference implementation; generates vectors/
vectors/     generated test vectors (JSON with hex), never hand-edited
core/        Rust workspace: protocol and crypto crates shared by apps and services
services/    aggregator, issuer, verifier host, delivery, blob store, open data, gallery (Rust); ledger (Go, Tessera)
apps/        ios/ (SwiftUI) and android/ (Jetpack Compose), on core via uniffi
sim/         headless simulator that runs the whole loop
tools/       scripts and CI helpers
```

Common commands live in the `justfile` (`just check`, `just vectors`, `just sim-fast`, `just sim-full`). Run `just --list` for the current set.

## Conventions

- Test data never contains real personal data. Polis open data is CC BY 4.0; credit it where it's used.
- Product vocabulary is fixed: context, channel, issue, position, argument, deck, card, deal, hand, release, ledger, shield, resident card, take, studio, gallery, unlocks.
- Write docs and specs in plain, short sentences. Specs say MUST/SHOULD only where conformance tests check them.
- When you finish a task, summarize what changed, what you verified and how, any seam touched, and open questions.
