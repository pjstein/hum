# 0052 · Message franking for reports

**Status:** proposed (W0-05, 2026-10-06) · `seam:` domain-separation strings, what leaves the phone

## Context

Moderators must be able to act on a reported message without reading everything, and a report has to prove the message was really sent, including any attachment. MLS gives every message a sender signature inside the ciphertext, which proves authorship to anyone who can see the plaintext. It does not prove the message passed through the delivery service, or when.

## Decision

Recorded in `docs/specs/chat.md` section 11:

- **Keyed commitment in the clear.** The sender draws a random 32-byte franking key, puts it inside the MIMI content under extension `"hum.frank"`, and sets the `PrivateMessage` authenticated data to `0x01 ‖ HMAC-SHA256(key, "hum/frank/1" ‖ group_id ‖ epoch ‖ content bytes)`. Recipients verify it after decrypting. The DS sees a random tag and nothing else.
- **Delivery stamp.** The DS signs `"hum/stamp/1" ‖ group_id ‖ seq ‖ received ‖ authenticated_data` with a `sign` key of its keyset, names the key ID in the response, and stores the stamp with the message.
- **Attribution from MLS.** A report carries the decrypted `AuthenticatedContent`, the epoch's `GroupContext` (so a moderator outside the channel can rebuild `FramedContentTBS`), the sender's credential and leaf key, the sequence number, receive time, stamp, stamp key ID and the DS manifest version. The chat identity binding in the credential plus the MLS signature attribute the message; the tag plus the stamp prove the DS delivered exactly that content to that channel at that time.
- **The tag never leaves the group.** `issue-map.md`'s `origin` on a promoted object is the salted MIMI message ID, not the franking tag, because the DS stores every tag beside its channel and time, and a logged signed object carrying the tag would let the DS name that object's author as a sender.
- **Reports go to a moderation channel**, an ordinary MLS group holding members with the `moderate` capability. History archives keep `AuthenticatedContent`, not bare plaintext, so archived messages stay reportable.

## Alternatives considered

- MLS signature alone. Proves authorship, not delivery or time, and cannot show the DS carried the message.
- A commitment in the ciphertext only. The DS could not countersign it.
- Server-side franking of the ciphertext hash. The reporter cannot show a third party that the ciphertext opens to the reported plaintext without revealing group keys.

## Consequences

- Every application message costs one HMAC and 33 bytes of authenticated data. Every send costs the DS one Ed25519 signature.
- Messages are non-repudiable inside the group, as MLS already makes them. Hum uses that rather than adding deniability, and the privacy screen says "What you say, signed."
- Open: whether a report should also prove the leaf was in the tree at that epoch.
