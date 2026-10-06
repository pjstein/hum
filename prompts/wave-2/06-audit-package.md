# W2-06 · The audit package

**Owns:** `docs/audit/`

Before real people use Hum, an outside cryptography and privacy review looks at it. Make that review fast, focused and cheap by handing reviewers exactly what they need.

## Assemble

- **Overview:** what Hum promises, in a page, with the threat model's assumptions stated plainly.
- **Scope:** the seams from `CLAUDE.md`, each with its spec sections, its code paths, its tests and vectors, and its twin-implementation results.
- **Specs:** the normative specs, with open questions and any rule that still lacks vectors.
- **Evidence:** the integration report, the twin report, both red-team reports with every finding's status, and the fuzzing results.
- **Dependencies:** every cryptographic and DP library, its version, why it was chosen, and its own audit history if any.
- **Questions for reviewers:** the places the team is least sure about, ranked. Be honest; it's the most useful part.
- **Reproduction:** how to build everything, bring up the local reference network, run the simulator and the attacks.

## Done when

`docs/audit/README.md` indexes all of it, a reviewer could start from it without asking where anything is, and the owner has it to send.
