# W1-10 · The Android app

**Owns:** `apps/android`
**Implements:** the same flows as W1-09, on the same API, for Android

## Read first

Everything W1-09 reads: `docs/ux/README.md`, `docs/ux/screens/`, `docs/ux/canvas/`, `docs/specs/app-api.md`, and `docs/design.md` "Product and UX". Read `prompts/wave-1/09-ios.md` too: the two apps should match screen for screen, and differences belong in a note in `docs/ux/README.md`.

## Build

- A Jetpack Compose app on a current target SDK, built against the fake core first and the real one as it lands.
- The same design system, the same swipe deck feel (gesture, lean, stamp, topic meters, buttons, undo, haptics), with the same no-nudge rules.
- Every board and path, plus the screens W1-09 designs for agents, files, settings and recovery. Coordinate through `docs/ux/README.md` so both apps share one design for them.
- Keys in hardware-backed Keystore (StrongBox where available) as `08-core-ffi` designs; passkey restore through Credential Manager; notifications that carry nothing identifying.
- Accessibility: TalkBack labels, font scaling, reduced motion, contrast.
- No dynamic code loading or over-the-air code updates. Aim for a reproducible build, and record what it would take.

## Tests

Screenshot tests against the board PNGs (layout and copy), UI tests for the participant and organizer paths, and the simulator's phone scenarios through the real core.

## Done when

The participant and organizer paths run end to end on a device against a local reference network, and screenshot and UI tests pass in CI.
