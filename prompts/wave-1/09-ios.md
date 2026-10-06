# W1-09 · The iOS app

**Owns:** `apps/ios`
**Implements:** every participant, organizer, deliberation, chat and studio flow in `docs/ux/`, on the API in `docs/specs/app-api.md`

## Read first

`docs/ux/README.md` (the visual language, every board, and the paths), every PNG in `docs/ux/screens/`, the board sources in `docs/ux/canvas/` for exact copy and interaction states, and `docs/design.md` "Product and UX".

## Build

- A SwiftUI app on the current iOS release, built against the fake core first and the real one as it lands.
- The design tokens from `docs/ux/README.md` as a small design system (colors, Archivo and DM Mono, spacing, 44 pt targets). Direction B only.
- **The swipe deck** is the heart of it: a card that follows the finger, leans and fades in its stamp (agree right, disagree left, unsure up), topic meters, buttons that do the same, undo, and haptics. Match `Swipe-Deck` and `Swipe-Gestures`. It must feel good. And it must not nudge: no running results before you vote, no reaction to which way you swipe.
- Every board, wired into the paths in `docs/ux/README.md`: onboarding and the practice card, the resident card, joining, the hub, the deck, your hand, the results deck, the release and its receipt, the shield, chat, the issue map and the flip card, authoring, organizer screens, the studio and gallery.
- Screens the canvas doesn't have yet (agents, files, settings and devices, recovery, empty and error states): design them in the same language, and add a note to `docs/ux/README.md` for each one.
- Keys in the Secure Enclave as `08-core-ffi` designs; passkey restore; notifications that carry nothing identifying.
- Accessibility: VoiceOver labels on every card and control, Dynamic Type, reduced motion (the swipe has a button path), contrast.
- No over-the-air code updates, no web views that run remote code.

## Tests

Snapshot tests of each screen against the board PNGs (layout and copy, not pixels), UI tests for the participant and organizer paths, and the simulator's phone scenarios through the real core.

## Done when

The participant and organizer paths run end to end on a device against a local reference network, and snapshot and UI tests pass in CI.
