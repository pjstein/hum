# Hum UX reference

These are snapshots of the UX spike canvas: https://claude.ai/artifact/U1CRFCYEKFnR8DGHvgWnmM (the living, clickable version; open the "Participant & trust" page and press Play on Welcome).

- `screens/` has a PNG of every board at 2× (390 pt wide phone frames).
- `canvas/` has the source of every board. Each is HTML with inline styles plus a small `Component` class holding its state and copy. The boards need the canvas runtime to render, so read them as specs for layout, copy and interaction states rather than running them.

**Direction B was chosen**: dark, editorial, data-first, played like a card game (Tinder-style swipe, inspired by the card sorting in *Reigns*). Direction A boards are kept only for contrast. Fun is a feature, as long as it never nudges an answer.

## Visual language (from the boards)

| Token | Value | Use |
| --- | --- | --- |
| Background | `#0F1115` | App background |
| Surface | `#181B21`, raised `#20242B` | Cards, sections, tab bars |
| Border | `#2A2F37`, inputs `#3A404A` | Dividers, outlines |
| Text | `#F3F1EA`; secondary `#B9BDC4`; tertiary `#8D939C` | |
| Accent | `#E8D44D` | Primary actions, highlights |
| Agree | `#6EA8FF` | Agree, "pro" |
| Disagree | `#FF9351` | Disagree, "con" |
| Card paper | `#F3F1EA` with ink `#0F1115` | Statement cards, deck cards |
| Type | Archivo 400–800 for UI; DM Mono for numbers, hashes and timestamps | |

Touch targets are at least 44 pt. Every swipe has a button equivalent, and there's an undo.

## Boards

| Board | Page | What it shows |
| --- | --- | --- |
| `P-Welcome` | Participant & trust | Welcome and a practice card. **Start of the participant path** |
| `P-Verify` | Participant & trust | Getting a resident card: the verifier, the attributes it issues, and the evidence it asks for, shown before you submit |
| `P-Join` | Participant & trust | Dealt into a context: what organizers can and can't see |
| `P-Budget` | Participant & trust | The privacy shield: yearly budget and the releases that included you |
| `P-Ledger` | Participant & trust | A release receipt: the ledger entry, its parameters, and checking your votes were counted |
| `B-Home` | Two directions | Context home and hub: Deck / Chat / Map tabs, the Organizer chip, and the tab bar (Contexts, Studio, Ledger, You) |
| `B-Vote`, `B-Release` | Two directions | Direction B voting and release, before the swipe deck replaced them |
| `Main`, `A-Vote`, `A-Release` | Two directions | Direction A (not chosen) |
| `Swipe-Deck` | Swipe deck | The deck: drag right to agree, left to disagree, up for unsure; topic meters; buttons and undo |
| `Swipe-Gestures` | Swipe deck | Gesture states: leaning right, leaning left, pushing up |
| `Swipe-End` | Swipe deck | Deck sorted: your hand |
| `Swipe-Reveal` | Swipe deck | The results deck: one card per statement, your vote next to everyone's, matched on your phone |
| `IBIS-Card` | Deliberate & chat | A position card: vote, flip to the strongest pro and con, re-vote |
| `IBIS-Map` | Deliberate & chat | The issue map: an issue, its positions, arguments and sub-questions |
| `IBIS-Author` | Deliberate & chat | Adding a position, pro, con or question; near-duplicate merge; posting as your chat name or unsigned |
| `Chat-Server` | Deliberate & chat | Context chat: channels, issue channels and organizers |
| `Chat-Channel` | Deliberate & chat | An issue channel: promote a message to the map; a dealt deck posted into the channel |
| `Chat-Privacy` | Deliberate & chat | What chat keeps private, and the two identities (chat name vs voting key) |
| `O-Create` | Organizer | Create a context: who can join, who sees results, floors |
| `O-Members` | Organizer | Members and invites, with noised counts only |
| `O-Compose` | Organizer | Build the deck: cards, release plan, what each size unlocks |
| `O-Plan` | Organizer | Unlocks and the deal schedule |
| `S-Gallery` | Studio & gallery | The gallery: takes ranked by how fair every opinion group finds them |
| `S-Studio` | Studio & gallery | Build a take: chart builder with error bars from the published noise |
| `S-Take` | Studio & gallery | A published take, pinned to its release |

## Paths

- **Participant:** Welcome → Resident card → Join → Millbrook home (`B-Home`) → Pick up the deck (`Swipe-Deck`) → Your hand (`Swipe-End`) → Results deck (`Swipe-Reveal`) → Full release → Ledger (`P-Ledger`) or Studio → Publish → Take.
- **From the hub:** the tab bar reaches Studio, Ledger and You (the privacy shield). The Chat and Map tabs reach `Chat-Server` and `IBIS-Map`.
- **Organizer:** the Organizer chip on `B-Home` → Unlocks (`O-Plan`) → Build the next deck (`O-Compose`) or Members. Creating a context: `O-Create` → `O-Members` → `O-Compose`.
- **Deliberation:** `Chat-Channel` → promote a message (author confirms) → `IBIS-Map` → `IBIS-Card` → the position is dealt into the next deck.

## Not designed yet

- Agent screens: catch-up, a facilitator agent in a channel, the agent membership event.
- Files: a channel's files, context folders, pin-to-folder from a message.
- Settings, devices and recovery (keys in secure hardware, passkey restore), notifications, empty and error states.
