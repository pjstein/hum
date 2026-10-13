# Proposed verifier component ABI spelling

Status: proposed; no normative spec or `KNOWN_ABIS` change.

The exact artifact is `proposed-verifier.wit`. It defines package
`hum:verifier@0.1.0`, interface `host`, and world `module`. The proposed manifest
`code.abi` is `hum:verifier/module@0.1.0`. Components import the interface instance
`hum:verifier/host@0.1.0`.

| Current semantic operation | Proposed interface function |
| --- | --- |
| `manifest.body` | `manifest-body` |
| `manifest.version` | `manifest-version` |
| `evidence.get` | `evidence-get` |
| `evidence.credential` | `evidence-credential` |
| `evidence.device` | `evidence-device` |
| `dataset.lookup` | `dataset-lookup` |
| `dataset.root` | `dataset-root` |
| `time.day` | `time-day` |

The eight signatures, four imported record types, two exported record types and
`decide: func() -> result<decision,rejection>` retain the spec's semantics.
No new operation, capability, secret or data field is added. Full three-part
SemVer and kebab-case names satisfy the component model's external-name grammar.

The alternative is to define four distinct imported interfaces named manifest,
evidence, dataset and time. That is valid but introduces more interface identities
than the existing spec's single host world. This proposal uses one host interface.

Before adoption: independent review, owner acceptance, then update the normative
runtime spec and verifier ABI allowlist together. Existing `@0.1` does not silently
alias `@0.1.0`. The reference exposes this adapter only through `proposed_host=`;
normal execution still refuses all imports.
