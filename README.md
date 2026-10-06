# Hum

A chat app with superpowers for groups that need to decide things. Conversation ratchets into an issue map, positions become decks of cards people vote on privately, and every deck ends in one differentially private release on a public ledger. No vote is ever attributable to anyone.

The name comes from IETF humming (RFC 7282): a chair reads the room's hum, and nobody is singled out.

## This repo, right now

This is the seed: the design, the first spec, the UX reference and the prompts that build everything else.

| Start with | Why |
| --- | --- |
| `CLAUDE.md` | Invariants, workflow and security seams for anyone (or any agent) working here |
| `docs/design.md` | The product and architecture |
| `docs/specs/manifest.md` | The first normative spec |
| `docs/ux/README.md` | Screens, visual language and paths |
| `docs/DECISIONS.md` | What's decided, proposed and open |
| `docs/SOURCES.md` | Living versions of these docs and the standards behind them |
| `prompts/README.md` | How the build runs: bootstrap, then three waves |

## Getting going

```bash
git add -A && git commit -m "Seed: design, manifest spec, UX reference, prompts"
claude "Read prompts/00-bootstrap.md and carry it out."
```

(Starting from `hum-seed.zip` instead? Unzip it, `cd hum` and `git init` first.)

Then run wave 0 with `prompts/wave-0/00-orchestrate.md`.

## License

Not chosen yet; see `docs/DECISIONS.md`. The Polis open data used in `docs/research/` is CC BY 4.0.
