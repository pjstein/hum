# core

The Rust crates shared by the phones and the services. The apps reach them
through `hum-ffi` (uniffi); the services and the simulator link them directly.

All crates live in `core/crates/` and belong to the single Cargo workspace at
the repo root (`/Cargo.toml`, see `docs/decisions/0001-repo-layout.md`).
`unsafe_code` is forbidden workspace-wide; `hum-ffi` is the one exception.

| Crate | Owner | Spec |
| --- | --- | --- |
| `hum-manifest` | W1-01 manifests and logs | `docs/specs/manifest.md` |
| `hum-log` | W1-01 manifests and logs | `docs/specs/manifest.md` (logs, witnesses) |
| `hum-cred` | W1-02 identity | `docs/specs/credentials.md` |
| `hum-ballot` | W1-03 aggregation | `docs/specs/ballot.md`, `docs/specs/shield.md` |
| `hum-release` | W1-03 aggregation | `docs/specs/release.md` |
| `hum-chat` | W1-05 chat | `docs/specs/chat.md` |
| `hum-store` | W1-06 storage | `docs/specs/storage.md` |
| `hum-ibis` | W1-07 deliberation | `docs/specs/issue-map.md` |
| `hum-take` | W1-11 studio and gallery | `docs/specs/take.md` |
| `hum-agent` | W1-12 agents | `docs/specs/agent-sponsor.md` |
| `hum-ffi` | W1-08 core FFI | `docs/specs/app-api.md` |

Most of these crates are security seams (see `CLAUDE.md`). Adding a
dependency to one needs the owner's approval.
