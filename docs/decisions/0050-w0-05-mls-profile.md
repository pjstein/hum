# 0050 · MLS profile for chat

**Status:** proposed (W0-05, 2026-10-06); the MLS libraries are accepted by the owner 2026-10-07 · `seam:` credential bytes, exporter labels

*2026-10-07:* Approved as seam dependencies: OpenMLS 0.9.0 with the pure-ciphertext wire format policy for the core, and `mls-rs` through its uniffi bindings for reference vectors. Previous status: proposed (W0-05, 2026-10-06).

## Context

`docs/design.md` fixes MLS (RFC 9420) for chat and one group per channel. The spec has to pick a ciphersuite, a credential shape, a wire-format policy and a content format before two implementations can interoperate. The design doc also says the delivery service must not be able to list a channel's members, which rules out any flow that puts credentials on the wire in the clear.

## Decision

Recorded in `docs/specs/chat.md` section 1 and 2:

- **Ciphersuite** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), the RFC's mandatory suite. It matches Ed25519 and SHA-256 everywhere else in Hum.
- **Credential** type `basic`, with the identity bytes a deterministic CBOR map: kind (human or agent), the chat identity key, a device ID, a display name, a binding signature by the chat identity key over the leaf key, and for agents the `agent-sponsor` version and lineage CIDs. For an agent the leaf key is the sponsor manifest's `agentKey`, as `agent-sponsor.md` requires. No resident card, no pseudonym, nothing a verifier issued.
- **Every handshake message is a `PrivateMessage`.** External commits are not used, because they are `PublicMessage`s carrying the joiner's credential. Joins go through a `join-request` answered by a member with the right capability.
- **KeyPackages are sealed blobs,** never stored at the delivery service, because they contain the credential.
- **Ratchet trees for large groups are sealed blobs** referenced from a private-use GroupInfo extension `hum_tree_ref` (0xF001).
- **Exporter labels** `hum/keyring/1` (16 bytes, context group only, as `manifest.md` already states) and `hum/delivery/1` (32 bytes, every group).
- **Content format** is draft-ietf-mimi-content, pinned at version 09 (July 2026). Version 09 was checked against 08 for the fields Hum uses: the `MimiContent` array, the flat `NestedPart` array with the `ExternalPart` field order, the dispositions and the message-ID derivation are unchanged; 09 only clarifies that the URI lengths in the message-ID input are octet counts (big-endian 16-bit). Hum types are `application/vnd.hum.<name>+cbor` single parts with integer-keyed deterministic CBOR bodies.
- **MLS implementation (proposed, owner's choice).** Per `docs/research/seam-libraries.md`: OpenMLS 0.9.0 with `PURE_CIPHERTEXT_WIRE_FORMAT_POLICY` in the Rust core, which makes every handshake message a `PrivateMessage` as this profile requires; and `mls-rs` driven from the Python reference through `mls-rs-uniffi` to generate the vectors that need group state (`chat/exporter`, the `chat/roles` commit matrix, `chat/frank` with real `AuthenticatedContent`, `chat/ds-api` commit sequences), so those vectors come from an implementation independent of the code under test. Known risks: no public audit of OpenMLS itself was found, and `mls-rs-uniffi` must be built from git and has not been checked for exposing authenticated data, exporters and private-use extensions; the fallback is the OpenMLS interop client, which is not independent.

## Consequences

- OpenMLS supports the suite and `basic` credentials; no custom credential type needs registering. The `hum_tree_ref` extension is private-use until registered.
- Joining a channel needs a member online to commit the Add. Large contexts should run a greeter agent. If the owner wants self-service joins without a greeter, the credential has to become pseudonymous per context first (open question 4 in the spec).
- A later MIMI draft is adopted by amending this decision, not by code.
