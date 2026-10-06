# W0-05 · Chat on MLS

**Owns:** `docs/specs/chat.md`

Specify Hum's chat profile on MLS: Discord-shaped channels with end-to-end encryption, the messages that carry the ratchet (promote-to-map, decks dealt, releases posted), and what the delivery service can and can't learn.

## Read first

- `docs/design.md`: "Chat layer", "Files and storage", "Agents as first-class participants", and the who-sees-what table
- `docs/specs/manifest.md`: "Blobs and storage" (sealed references, keyrings and the `keyring/1` exporter label)
- MLS (RFC 9420) and its architecture (RFC 9750); the MIMI content format (draft-ietf-mimi-content), including ExternalPart
- `docs/ux/screens/Chat-Server.png`, `Chat-Channel.png`, `Chat-Privacy.png`, `B-Home.png`

## Cover

- **Groups:** each channel is its own MLS group; one all-members group per context carries the keyring and context-wide events. Ciphersuite choice. How channels are created, listed (a channel directory nobody outside can read), archived and deleted.
- **Identity and devices:** the chat name as the MLS credential; each device and each shared agent is a visible leaf; adding and removing devices; what a new device can read.
- **Roles and permissions:** how context roles become who can add members, post, pin, moderate and manage files, and how phones reject operations from members without the right role.
- **Message content:** use the MIMI content format for text, replies, reactions, edits, deletes and attachments (ExternalPart carrying a sealed reference). Define Hum's own content types: promote-to-map proposal and author confirmation, deck dealt, release digest, file operations (a folder is a channel whose messages are file operations), agent membership event.
- **History:** newcomers see messages from when they joined unless the context's policy adds history as an encrypted archive in storage; the archive format and how its key reaches them.
- **Moderation:** message franking so a report proves what was sent, covering attachment references; what moderators see; removal.
- **Delivery service:** its API, what it stores and for how long (it's a short-term queue; storage is long-term memory), padding, and how it authorizes sends without being able to list a channel's members (the design doc requires anonymous credentials here; say how, for example with per-channel anonymous tokens, and what MLS handshake metadata still leaks). Fetches through OHTTP.
- **Scale:** what changes when a channel has thousands of members (commit sizes, fan-out, history).
- **Search** runs on the phone; nothing about it leaves.

## Done when

`chat.md` defines every Hum content type byte for byte, the delivery service API, and the metadata the service sees in a table matching the design doc; vectors are listed; open questions are filed; and the `spec-reviewer` subagent has no blockers left.
