# 0042 · Positions are revisable until dealt, then withdraw-and-replace

**Status:** proposed (W0-04, 2026-10-06)

## Context

`manifest.md` leaves open whether a position can be revised by version or only withdrawn and replaced. The issue is what happens to a position already dealt into a deck: votes refer to exact words, and a release annotates the words voted on.

## Options

**A. Never revise.** Any change is a withdrawal plus a new object. Simple, but a typo in a fresh position costs the author a new lineage and the map fills with replaced stubs.

**B. Always revise by version.** The author publishes version 2 with new text. A deck pins a version, so an open deck keeps the old words, but the map would then show words nobody voted on next to a release's annotation, and the "same" card could read differently on the map and in the deck.

**C. Revise until dealt, then withdraw-and-replace.** An object's text, parent and keyring epoch may change by version until a deck manifest pins the object. From that log position on, those fields are frozen; only state (withdrawn, merged, hidden) can change. New words are a new object with `refs.replaces` naming the old one.

## Decision

Option C.

The dealt test is: any deck manifest version logged before the new object version's log position pins the object's version in its statements. A deck draft counts, so composing a deck is what freezes wording. That gives organizers a clear moment to tell authors "this is going in as written".

Authorship of later versions is proven by a per-object edit key committed in version 1, plus a fresh authorship proof of the same form as version 1. The edit key is derived from a per-person edit root (backed up with the chat identity key) and the hash of version 1's canonical envelope with the `editKey` field stripped (the CID itself would be circular, since it hashes the key), so any of the person's devices can recompute it from the logged object. It is what lets an unsigned author revise without linking anything. The context authority revises without it, through moderation versions that may change state but never text.

## Consequences

- A revised-before-dealt position has one lineage and one annotation. A replaced-after-dealt position has two lineages, and the map shows the chain.
- A withdrawn position that was already dealt stays in its deck and its release. The release reports its CID; whether the release carries text is for `release.md` (filed as an open question there).
- Arguments follow the same rule: frozen once their position's deck is dealt, because the card back shows them.
- `deck.md` must pin positions and arguments by version CID, and may pin only objects whose latest logged version is `active`.
- Organizers can freeze someone's wording by drafting a deck that pins it. The author's remedy is withdraw-and-replace, which is cheap.
