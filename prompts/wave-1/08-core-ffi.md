# W1-08 · The app-facing core API

**Owns:** `core/crates/hum-ffi`, `docs/specs/app-api.md`
**Implements:** the single API both apps use, over every other core crate

The iOS and Android apps should be thin: all protocol, crypto, storage and state logic lives in the Rust core. Define and build the API they call, and get it to them early so they never wait on you.

## Build

- **`app-api.md` first.** An async API organized by what the screens need (see `docs/ux/README.md`): onboarding and recovery, resident cards, contexts and membership, the hub, decks and hands, the swipe deck's card stream, results decks and releases, the shield, chat and channels, files, the issue map, the studio's queries, agents, settings and devices. Include an event stream for things that arrive (messages, deals, release rounds, membership events).
- **A fake implementation** of the whole API with realistic data from the UX boards (Millbrook Tenants Union, the Fall check-in deck), shipped in week one so the apps can build every screen against it.
- **The real implementation,** wiring each area to its crate as the crates land.
- **Bindings with uniffi** for Swift and Kotlin, building into an XCFramework and an Android library, in CI.
- **Secure hardware:** phones' secure elements mostly support P-256, not Ed25519. Design how keys are protected (for example, a hardware-bound P-256 key that wraps the protocol keys), how passkeys restore an account, and record it; this is a seam.
- **Background work:** release rounds need phones to act after a deck closes, and chat needs delivery. Specify how notifications wake the app without revealing who is in which context to the push providers (opaque wake-ups, fetched through OHTTP), and what happens when a phone misses a round.

## Seams

Key storage and wrapping, recovery, and anything deciding what leaves the phone.

## Done when

Both apps build against the fake from early on; the real implementation passes the simulator's phone scenarios through the same API; bindings build in CI.
