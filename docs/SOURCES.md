# Sources

Everything Hum was designed from. The repo copies are snapshots taken on 2026-10-06; the living versions are on claude.ai and may have moved on. If your session has the Artifact tool, read the living version before relying on a snapshot, and note any difference in your summary.

## Project artifacts

| What | Living version | Snapshot in this repo |
| --- | --- | --- |
| Design doc ("Hum — Design") | https://claude.ai/code/artifact/65a5453d-4d95-4084-9bae-f072be3aa62f | `docs/design.md` (rev 41) and `docs/diagrams/` |
| Manifest spec ("Hum Manifest Spec — Draft 0.1") | https://claude.ai/code/artifact/2d2835ef-010f-4dc8-92b1-5eca6636c9a8 | `docs/specs/manifest.md` (rev 29) |
| UX spike canvas | https://claude.ai/artifact/U1CRFCYEKFnR8DGHvgWnmM | `docs/ux/` (screens and board sources) |
| DP feasibility study | (delivered as `dp_polis_experiment.zip`) | `docs/research/dp-polis/` |
| Decisions so far | — | `docs/DECISIONS.md` |

The design doc is the product and architecture overview. The manifest spec is the first normative spec; every later spec builds on its envelope, CIDs, signatures, logs, blobs and floors. Diagrams in the snapshots are PNGs of the drawings in the living docs.

## Data

- Polis open data, https://github.com/compdemocracy/openData (CC BY 4.0). Used by the DP study and by the simulator's replay scenarios. Credit it wherever its data appears.

## Standards and drafts the design relies on

| Topic | Reference |
| --- | --- |
| Deterministic CBOR | RFC 8949 §4.2.1 |
| COSE signatures | RFC 9052 |
| Ed25519 | RFC 8032 |
| Transparency logs | RFC 9162; C2SP tlog-checkpoint, tlog-cosignature, tlog-witness and tlog-tiles (c2sp.org), as used by Tessera |
| Group messaging | MLS, RFC 9420; architecture, RFC 9750 |
| Message content and attachments | draft-ietf-mimi-content (ExternalPart); draft-robert-mimi-attachments |
| Oblivious HTTP | RFC 9458 |
| Anonymous tokens | Privacy Pass, RFC 9576 (architecture), RFC 9577, RFC 9578 |
| Private aggregation | IETF DAP (draft-ietf-ppm-dap) and Prio3 (draft-irtf-cfrg-vdaf) |
| Anonymous credentials | BBS signatures (draft-irtf-cfrg-bbs-signatures) and its pseudonym extension; Semaphore |
| Blind signatures (fallback option) | RFC 9474 |
| Padding | Padmé, from "Reducing Metadata Leakage from Encrypted Files and Communication with PURBs" (arXiv 1806.03160) |
| The name | RFC 7282, "On Consensus and Humming in the IETF" |

## Libraries named in the design (proposed, not yet decided)

OpenMLS (Rust MLS), OpenDP (Rust DP library with the Gaussian mechanism and zCDP accounting), Tessera (Go transparency-log library from transparency-dev), coset (Rust COSE), uniffi (Rust bindings for Swift and Kotlin; Mozilla's uniffi-bindgen-react-native exists if a cross-platform UI is ever reconsidered). Check each one's current release and maintenance before adopting it, and record the choice in `docs/decisions/`.
