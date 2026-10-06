# W2-03 · Privacy red team

**Owns:** `redteam/privacy/`, `docs/reports/privacy-red-team.md`

You are the adversary. Try to learn how a specific person voted, or to link their identities, using only what a given party could really observe. Report findings; don't fix them.

## Read

`docs/threat-model.md`, `docs/design.md` "Privacy model and trust" and "Differential privacy design", the specs, and the simulator's records of what each service saw.

## Attack, as each adversary in the threat model

- **The public, with releases only:** reconstruction and membership inference across many releases of one context, across contexts that share members, and across tiers (does a breakdown cell or the map leak a small group?). Composition across a year against the shield.
- **Other members who know you:** they know everyone's votes but yours (the planted-members case). Measure how much a release moves their belief about your vote, against what ε promises.
- **The organizer:** the noised daily count, invite and approval records, timing of activity against the deck, the issue map's authorship.
- **The operator in phase 1:** pseudonymous ballots plus every service's metadata (delivery timing, blob-store sizes and timing, ledger lookups, push wake-ups, relay logs if the relay is theirs). Try to join a voting pseudonym to a chat name or a resident card.
- **An issuer or custom verifier:** link issuance to later presentations; over-collect evidence through the sandbox.
- **A compromised personal or shared agent:** exfiltrate votes, hands or a membership list.
- **A malicious client:** loosen floors for its own user and see what an honest aggregator and ledger do.

## Measure, don't just argue

Each attack gets code in `redteam/privacy/` that runs against the simulator, a measured success rate, and a comparison with what the design promises. "Works in theory" findings say what would make them practical.

## Report

Findings by severity, each with the attack, the evidence, the invariant or guarantee it breaks, and a suggested mitigation. Include attacks that failed and why; they're evidence for the audit.
