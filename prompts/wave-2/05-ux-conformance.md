# W2-05 · UX conformance and the no-nudge review

**Owns:** `docs/reports/ux.md`

Check that both apps are what the canvas promised, that they're accessible, and that the fun never nudges an answer.

## Do

1. Walk the participant, organizer, deliberation and studio paths from `docs/ux/README.md` on both apps against a local reference network. Compare each screen with its board PNG and source for layout, copy and states. List differences, and say which are improvements to fold back into `docs/ux/`.
2. **No-nudge review:** nothing shows a running result before you vote; the app doesn't react to which way you swipe; unsure is a full answer; card order doesn't push a pattern; the results deck's "with the majority so far" counter is flagged for testing since it may push conformity. Check copy everywhere for loaded wording.
3. **Privacy legibility:** at every point where something leaves the phone, does the screen say what and to whom? Check the resident card, joining, the shield, the receipt, chat privacy and agent membership against the design doc.
4. **Accessibility:** screen readers through every path, the button path for every swipe, Dynamic Type and font scaling, reduced motion, contrast.
5. **Feel:** the swipe deck's physics, haptics and timing on real devices. Describe what feels off concretely enough to fix.

## Done when

`docs/reports/ux.md` lists every difference, accessibility failure and nudge risk with a screenshot and a fix, and the app workstreams have them as tasks.
