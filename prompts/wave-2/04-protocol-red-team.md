# W2-04 · Protocol red team

**Owns:** `redteam/protocol/`, `docs/reports/protocol-red-team.md`

Attack the integrity of the system: make people act on something false, make a bad release look good, or make the network say different things to different people. Report findings; don't fix them.

## Attack

- **Logs and witnesses:** show different histories to different phones; fork a lineage; pass off an old version as the latest; get a manifest acted on before it's logged; collude with one witness.
- **Manifests and keys:** non-canonical encodings, signature replay across domains, key compromise before and after rotation, pre-rotation bypass, equivocating authorities, reference cycles and depth bombs, oversized bundles.
- **Releases:** publish with fewer voters than the floor, release twice per deck, change a deck's plan after it opens, sign with one aggregator, skew noise, tamper with tables after logging, break receipts.
- **Ballots and credentials:** double voting across devices or after re-issuance, replaying ballots, exceeding the contribution cap, voting with an agent's credential, voting after removal.
- **Chat and storage:** forge a message an honest reporter can franking-verify, inject a file operation without the role, serve wrong bytes for a CID, delete someone else's blob, exhaust quotas, flood the issue map with agents.
- **Availability:** what one malicious service can stop, and whether phones fail safe (refuse) rather than open.

Each attack gets code in `redteam/protocol/` that runs against the simulator or the local reference network.

## Report

Findings by severity with the attack, evidence, the spec rule it defeats (or the missing rule), and a suggested fix. Include attacks that failed.
