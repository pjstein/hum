# Decisions

The decision log for Hum. **Accepted** decisions came from the project owner and aren't relitigated without them. **Adopted in the docs** decisions are written into `docs/design.md` or a spec; change them with a spec change, not in code. **Proposed** decisions are recommendations waiting for the owner's approval in wave 0. **Open** decisions block something and need the owner.

New decisions go in `docs/decisions/NNNN-short-title.md` (context, decision, consequences, status), with a line added here.

## Accepted

1. **Name: Hum.** From IETF humming (RFC 7282): a chair reads the room's hum, and nobody is singled out.
2. **A chat app with superpowers.** Conversation ratchets into structure and back: chat → issue map → deck → release → chat. Things shouldn't get lost in chat; they should ratchet up into decisions.
3. **No vote is ever attributable to a person.** The public dataset is the releases, never the votes. Anyone can explore releases in a studio and a Kaggle-like gallery.
4. **Native apps only** (iOS and Android), for the device-level security a native app allows.
5. **UX direction B:** dark, editorial, data-first, played like a card game (Tinder-style swipe, *Reigns*-style card sorting). Fun is a feature.
6. **Contexts:** anyone can create one, configure permissions and membership, and deal statement sets; there is also a Global context.
7. **IBIS deliberation** (issues, positions, pro and con arguments) generates what people vote on; some statements are artifacts presenting a case.
8. **Chat is end-to-end encrypted** and Discord/Slack-shaped (channels, roles), beyond simple groups.
9. **Agents are first-class participants** in every process and conversation.
10. **Protocol-first.** Everything is an open protocol. Launch on one reference network, designed to federate; federation itself comes later.
11. **Verifiers are extensible from day one.** Some (like district) are core infrastructure; context administrators can run their own from the start.
12. **Context-level shared file storage,** which also backs chat.
13. **Built by one person directing agents, at full scope,** in three waves: contracts, parallel build, integrate and attack.

## Adopted in the docs

- Manifest envelope: deterministic CBOR, CIDs (0x01 + SHA-256), detached COSE_Sign with Ed25519 under the `manifest/1` domain string, keyset lineages with pre-rotation, pinning by CID, transparency logs with witness cosignatures. See `docs/specs/manifest.md`.
- Differential privacy: user-level ρ-zCDP Gaussian mechanism, δ = 10⁻⁶; one release per deck; every release is a sum, so central DP ships first and two-server aggregation (DAP, Prio3) replaces it later without changing the math.
- Size gates: tallies 100 voters, common ground 300, map and groups 800, breakdown cells 300, real-data checks 5,000.
- Three identities, never linked: resident card, per-context voting pseudonym, chat name.
- Agents never vote; agent content is labeled; adding a shared agent is a visible membership event.
- Each channel is its own MLS group; message franking for moderation.
- Storage: sealed (encrypted, content-addressed) and public blobs; keys travel in references, never in manifests, logs or store requests; a folder is a channel of file operations.
- Floors are enforced at the edges (phones, aggregators, ledgers) and can only get stricter.

## Proposed (approve or replace in wave 0)

- **Rust core** shared by phones and services, exposed to the apps through uniffi; **SwiftUI** and **Jetpack Compose** apps on top. Over-the-air code updates stay off.
- **Python reference implementation** that generates every test vector, independently of the Rust code.
- **Go ledger on Tessera,** which also serves as the second, independent implementation of manifest verification.
- Libraries: OpenMLS, OpenDP, coset; others chosen per workstream and recorded here.
- Per-context voting pseudonyms: BBS with pseudonyms, or Semaphore-style group proofs. W0-02 recommends one.

## Open

- **Operator and Helper:** who runs the reference network, and which independent party runs the second aggregator.
- **Privacy targets:** ε per release (drafted at ε 4 / ρ 0.254) and the yearly shield (placeholder ε 20).
- **Witnesses at launch:** who runs them, and whether two cosignatures is enough.
- **Licenses:** code (AGPL-3.0 or Apache-2.0), specs and release data (CC BY 4.0 suggested).
- **Outside cryptography review:** who, and when before real users.
- **Hosting** for the reference services.
- **First contexts** to launch with.
