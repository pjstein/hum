# W1-05 · Chat

**Owns:** `core/crates/hum-chat`, `services/delivery`
**Implements:** `docs/specs/chat.md`, the delivery-service part of `services.md`

## Build

- **`hum-chat`:** the Hum chat profile on OpenMLS: one MLS group per channel plus the all-members group; the encrypted channel directory; roles enforced on every received operation; devices and shared agents as visible members; MIMI-format content and Hum's content types (promote-to-map proposal and confirmation, deck dealt, release digest, file operations, agent membership event); message franking; history archives through `hum-store`; checkpoint-hash exchange for `hum-log`; on-device search.
- **`services/delivery`:** a short-term queue that authorizes sends with anonymous per-channel tokens, pads sizes, can't list members, serves fetches through OHTTP, and keeps nothing longer than the spec allows.
- **Keyring export:** the `keyring/1` exporter on the all-members group, handed to `hum-store`.

## Tests

MLS interop against OpenMLS's own test vectors; Hum's chat vectors; a simulator scenario with a context of hundreds of members across channels, with joins, removals and device changes; the leak check confirms the delivery service saw only ciphertext, timing and channel tokens; franking reports verify; a removed member can't read anything sent after removal.

## Seams

The MLS ciphersuite and configuration, franking, token handling, and anything that touches keys.

## Done when

Simulated members chat across channels, promote messages to the map, receive decks and digests, and survive membership churn, with the delivery service learning no more than the spec says.
