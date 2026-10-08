# 0010 · Body conventions for context, deck and release manifests

**Status:** proposed (W0-01, 2026-10-06); the open sampler-input question is decided: option B, accepted by the owner 2026-10-07 · `seam:` canonical encoding, signing (two signers on a release)

*2026-10-07:* The owner chose option B for the sampler input: a rational upper bound σ_r, called as σ, charged at the plan's ρ. W0-01 is making it normative in `release.md`. Previous status: proposed (W0-01, 2026-10-06).

## Context

The manifest spec fixes the envelope but leaves each body spec to choose how it writes rationals, σ values and tables, and it registers `release` as "signed by both aggregator authorities" while the envelope has a single `authority` field.

## Decision

1. **Rationals.** A `rat` is a CBOR array `[num, den]` of two uints in lowest terms, `den ≥ 1`, both below 2⁶⁴. Not in lowest terms fails the schema check (step 4); step 2 cannot catch it because the bytes re-encode identically. JSON view `"num/den"`. Every ρ, δ and blur value is a `rat`; nothing in a signed body is floating point.
2. **`RHO_MAX` = 127/500.** The exact ρ for ε 4 at δ 10⁻⁶ is 0.25398…; the design doc rounds to 0.254, which is ε 4.00054 (binary64). The constant is the rounded value, as written in `CLAUDE.md`. Displayed ε is rounded half to even to two decimals; vectors carry the binary64 value.
3. **σ is a rational upper bound** (accepted by the owner 2026-10-07). With σ² = p/q in lowest terms, p = Δ²·den and q = 2·num, σ_r = n/2²⁰ where n is the least integer with n²·q ≥ p·2⁴⁰, all in integer arithmetic. The sampler (OpenDP `sample_discrete_gaussian(scale: RBig)` or libprio `DiscreteGaussian::new(std: Rational)`) is called with σ_r; the part's `rho` stays the plan's since Δ²/(2σ_r²) ≤ ρ. `sigma` in manifests is round(σ_r × 10⁶), ties to even, display only (covariance divided by `covScale`). Sampling from a binary64 value, or from σ rather than σ_r, is non-conformant. Δ² is `K+1`, `2·K_m`, `K_r`, `R+1`, or `Δ_cov²`.
4. **Tables are Parquet** with the schemas in `release.md`, key-value metadata prefixed `hum.`, raw signed noised sums, and CID columns as 33-byte binaries. The media type is `application/vnd.apache.parquet`.
5. **Two signers on a release.** The envelope's `authority` is the Leader aggregator; the body field `helper` is the Helper authority; verification step 6 for type `release` requires the `sign` threshold of both keysets (`release.md`, rule R9). The manifest spec's registry row and verification section should say this explicitly.
6. **A deck does not pin aggregators.** The context version it pins names the pair. The manifest spec's deck example shows an `aggregators` ref; the registry row ("Context version, statement list") is what the deck spec follows, and the example should drop the ref.
7. **Domain strings** new in these specs are namespaced `hum/…/1`: `hum/results-key/1` (HKDF `info` for the results key, not an exporter label), `hum/results-keybox/1` (HPKE info). The manifest spec's `manifest/1` predated the convention and was renamed `hum/manifest/1` under ADR 0105.

## Sampler input: accepted by the owner 2026-10-07

Option B from the three options filed on 2026-10-06 (expose or vendor a σ² sampler; a rational upper bound σ_r; another exact sampler). Item 3 above is the adopted rule; `release.md` "Noise" is normative. Revisit if OpenDP exposes a σ² entry point.

## Consequences

- W0-08 implements `rat` once and reuses it; the σ rounding rule gives byte-exact vectors.
- Items 5 and 6 are edits to `manifest.md` that W0-01 does not own; W0-10's cross-spec review should carry them.
