# 0041 · Log every authored object individually

**Status:** proposed (W0-04, 2026-10-06)

## Context

`manifest.md` lists batching of participant-authored objects as its most consequential open question: log each issue, position and argument version as its own entry, or log a per-context batch root on a schedule. The worry is volume. The two choices prove different things.

## Options

**A. One log entry per object version.**

What the log proves: that this exact version was logged at this position; its order relative to every other version in the same lineage and to the deck that pinned it; and that no second version with the same number was logged first (non-equivocation per object). A phone lists a whole map by asking the log for entries with the context's authority and the three map types, with no index server to trust. An author submits directly, so nobody can silently drop their post.

What it costs: one entry per version. A lively context might produce hundreds a week; across the network, tens of thousands a day, which is small next to certificate transparency logs and well inside what a tile-based log such as Tessera serves. It also publishes a members-only context's activity rate, since entries carry type and authority.

**B. A per-context batch root on a schedule.**

A batcher (run by the context or the operator) collects object CIDs, builds a Merkle tree over them, and logs the root as one manifest, say hourly. The log proves the batch root was logged; the batcher's tree proves an object was in the batch. Order within a batch is the batcher's word. Non-equivocation holds per batch, not per object, so two conflicting versions in one batch are detected only by whoever reads the whole batch. A dropped object is invisible to everyone but its author. Objects aren't usable until the batch lands, which adds up to a schedule's worth of latency to a flow that should feel like chat. Listing a map needs the batcher's trees, which means a server that is more than a cache.

## Decision

Option A. Log every object version individually.

Volume is not the deciding factor, because the log batches writes internally (tlog-tiles) and serves proofs from tiles. The deciding factors are that A keeps authors independent of a batcher, keeps order and non-equivocation per object, and lets a phone sync a map straight from the log.

## Consequences

- `issue-map.md` assumes per-object entries throughout: rate limits are counted at the log, the dealt test uses log positions, and map sync is a log query.
- A members-only context's object count per day is public. If that turns out to matter, a context could later opt into a batch-root type without changing the object format; the objects would still be manifests, pinned by the batch instead of logged directly. Nothing in draft 0.1 forecloses that.
- The log should run the cheap step-10 rules for these types before appending (filed with W0-07), so a bad version can't break a lineage for honest clients.
- The simulator should model a context at 1,000 members and 50 objects a day to confirm proof-fetch costs on a phone stay in the tens of kilobytes per sync.
