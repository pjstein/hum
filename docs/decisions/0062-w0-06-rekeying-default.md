# 0062 · Re-keying after a removal: lazy by default, eager per sensitive folder

**Status:** proposed (W0-06, 2026-10-06)

## Context

`docs/specs/manifest.md` leaves open whether removing a member should only rotate the keyring (lazy) or also re-encrypt existing files (eager), and who pays for it. The storage spec has to pick a default so phones behave the same way.

## Decision

- **Default is lazy.** A removal advances the keyring and rotates every channel's MLS keys. Existing blobs are not touched.
- **Eager re-keying is a per-folder opt-in.** A folder marked `sensitive` is re-keyed when a member is removed from its group: every current version is fetched, re-sealed under a fresh key, re-uploaded and re-announced with a `version` operation; earlier versions and every old blob are deleted by a context delete order.
- **The removing member's phone does the work.** It commits the removal, so it is online and holds the folder. The context's storage policy caps sensitive folders (`sensitive_max_bytes`, suggested 256 MiB) so the work is bounded.

See `docs/specs/storage.md` §10.

## Consequences

- Most removals cost nothing beyond an MLS commit and one exporter call.
- A removed member keeps anything they already downloaded, in both modes. Eager mode only helps when they kept references but not bytes, and only once the old blobs are deleted; the UI shows a folder as "re-keying" until the delete order is confirmed.
- Re-keying needs a delete order signed by the context's sign threshold, so an organizer without a sign key has to ask one who has it.
- `context.md` needs the `sensitive_max_bytes` field; `chat.md` needs a way to set the `sensitive` flag on a folder.
