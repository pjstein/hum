# W2-02 · Twin implementations

**Owns:** `twins/`, `docs/reports/twins.md`

Bugs in the security seams hide where one implementation and its own tests agree with each other. For each seam, build a second implementation from the spec alone and compare it with the production code on huge numbers of inputs. Every disagreement is either a bug or an ambiguous spec.

## Do

For each of these, launch a subagent that reads **only** the relevant spec sections, `vectors/` and `CLAUDE.md` (never the production code), and writes an independent implementation in a different language from production (Python, Go or TypeScript):

- canonical CBOR, CIDs and manifest verification (Go already exists in the ledger; add a third only if the Go and Rust ones share a dependency that could share a bug);
- the sealed blob format and sealed references;
- ballot encoding, contribution capping and the shield's accounting;
- release assembly given fixed noise inputs: tiers, size gates, table contents, noise-aware rankings;
- the issue-map and take validation rules.

Then build a differential harness that generates random and adversarial inputs (property-based and fuzzer-driven), runs both implementations, and records every disagreement.

## Resolve each disagreement

Find which side follows the spec. If the spec allows both, the spec is ambiguous: write the fix as a proposed spec change in `docs/decisions/` and add a vector that pins it down. Production fixes go to the owning workstream.

## Done when

Each twin has run against production for a meaningful number of cases with every disagreement resolved, new vectors are in `vectors/`, and `docs/reports/twins.md` lists what was found.
