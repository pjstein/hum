# 0023 · Per-person backup, the chat identity key, one voting device, and no transfer of hand or shield

**Status:** proposed, revised after review (W0-02, 2026-10-06). Phone-to-phone transfer and two voting devices confirmed off in draft 0.1 (owner, 2026-10-07). **The two-phone residual risk is accepted by the owner for draft 0.1 (2026-10-08): accept and disclose** · `seam:` key storage; what leaves the phone · **two items need the owner's explicit decision**

*2026-10-08:* The owner chose "accept and disclose" for the two-phone residual risk. It is stated in `docs/threat-model.md` and `shield.md`. Device-bound cards stay a filed alternative, not adopted.

*2026-10-07:* Confirmed off in draft 0.1; the alternatives stay open for a later decision. The residual risk is not yet accepted. Previous status: proposed, revised after review (W0-02, 2026-10-06).

## Context

A lost phone must not cost a person their chat identity, their issue-map edit keys or their resident cards, which issuer dedup would block them from re-obtaining for `validity` plus 30 days. `chat.md` and `issue-map.md` leave the backup of the chat identity key and the edit root to `credentials.md`. Invariant 1 says nothing but a ballot to an aggregator ever carries a vote, a hand or a shield. The design doc says keys live in the phone's secure hardware. The first draft allowed a direct phone-to-phone transfer of hand and shield; the review pointed out that this is an exception to invariant 1 and needs the owner, not a spec.

## Decision (draft 0.1)

1. **What is backed up:** the chat identity private key, the edit root, every card with its messages and nym secret, and the list of context lineages the person is in or left within the last 365 days (the shield's restore needs them). Nothing about votes: no hand, shield, receipt, card order or selection. Expired cards are deleted from the phone and the next backup.
2. **How:** sealed with the storage spec's blob format under a fresh key, that key HPKE-wrapped to an X25519 key derived from a 12-word recovery phrase with Argon2id (64 MiB, t = 3). Written into the app's platform-backed-up container once a day at a random time, never at the moment of a join, leave or renewal; no Hum service ever receives it or a locator for it.
3. **Hardware:** per-device keys (MLS leaf keys, device attestation key, the key that wraps secrets at rest) are hardware-bound. Per-person secrets are software keys stored encrypted under the hardware-wrapped key, because they must survive the device. This is how "keys in secure hardware" is read.
4. **One voting device:** cards and the shield live on one device at a time. A second device that will only chat receives a chat-only export (chat identity key and edit root, nothing else), so it cannot become a voting device by accident. A restore of the full backup makes the restoring device the voting device.
5. **No transfer of hand or shield off the phone.** Draft 0.1 has no device-to-device transfer of votes, receipts or the ledger. A new phone restores the backup and rebuilds the shield conservatively (ADR 0025).

## Why

- Putting the shield or hand in any backup or channel, encrypted or not, is what invariant 1 forbids. The conservative rebuild loses precision, never the guarantee.
- Two voting devices would each track only what they sent, and no channel is allowed to carry a shield between them.
- The phrase-derived key keeps the platform vendor out of the backup. Daily random-time writes keep the platform's timestamps from lining up with the delivery service's commits.

## For the owner: two alternatives, each an exception

- **Direct device-to-device transfer of hand, shield and receipts** over a local encrypted channel, with the source deleting its copy. It would give a new phone the exact ledger instead of an estimate that can show a person in a busy context as spent for a year. It is an exception to invariant 1 as worded and would need a specified channel (handshake, authentication, format). Not in draft 0.1.
- **Two voting devices.** Not in draft 0.1 and not specifiable without a shield channel. The residual risk that remains even now: a person who restores the full backup onto a second phone while keeping the first has two ledgers, each missing the other's entries; they still count once per deck (duplicate nullifier), but the two phones together can spend up to twice one shield across different decks. An unmodified app can do this. The owner should accept it explicitly, or ask for device-bound cards (a hardware key hashed into a card message with a proof of possession), which would make every phone loss a re-issuance that dedup blocks for `validity` plus 30 days.

## Consequences

- `chat.md` §2.3 names the chat-only export as the way a second device gets the chat key and says voting is single-device.
- The simulator's leak checker covers `shield.md` S10 and `credentials.md`'s storage table; a device-switch scenario must restore, not transfer.
- Argon2id parameters and the word list are seam choices; the reference implementation uses them as written.
