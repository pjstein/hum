# 0033 · Attributes declare gate-only or breakdown exposure

**Status:** proposed (W0-03, 2026-10-06)

## Context

The design doc says a unit number can gate entry but never appears in a breakdown, under the 300-voter cell gate. The verifier spec needs a rule a conformance vector can check, because the phone, not the verifier, decides what it discloses, and the aggregator needs to know which attributes may form cells at all.

## Decision

Every attribute carries `exposure`, either `gate` or `breakdown`. Gate attributes are only proven in zero knowledge against an entry policy. Breakdown attributes may additionally be disclosed, with the person's per-context consent, when a deck's release plan names them. Rules: `uint` attributes are always gate; `enum` and `band` attributes with more than 64 values are always gate; exposure may move from breakdown to gate in a later version, never the reverse. The 300-voter cell gate is enforced by the aggregator per cell and lives in `release.md`.

## Consequences

- Fine-grained identifiers (unit, roster row, code) are structurally unable to reach a breakdown.
- Breakdown planning is bounded: a deck can enumerate possible cells from the manifests alone.
- The 64-value limit is a planning bound, not a privacy bound; the cell gate does the privacy work. It can be tuned.
- `credentials.md` must carry disclosed breakdown values beside the ballot in a way that keeps them under the pseudonym and inside the release's budget.
