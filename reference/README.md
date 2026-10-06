# reference

The Python reference implementation of Hum's specs, and the only source of
`vectors/`.

**Owner:** W0-08 (reference and vectors).

It is written from `docs/specs/`, never from the Rust, Go or app code, so it
can act as an independent second opinion. Managed with `uv`:

```bash
uv sync                      # from this directory
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run hum-vectors --out ../vectors
```

From the repo root, `just vectors` regenerates `vectors/` and `just check`
fails if the committed vectors differ from a fresh run.
