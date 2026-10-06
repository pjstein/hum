# W1-11 · Studio and gallery

**Owns:** `core/crates/hum-take`, the ranking side of `services/gallery`
**Implements:** `docs/specs/take.md`, the gallery-index part of `services.md`, and the studio and gallery boards (`S-Gallery`, `S-Studio`, `S-Take`)

Anything built on a release costs no one any privacy, so the studio can be generous. Make it easy and honest to explore releases.

## Build

- **`hum-take`:** a query and chart spec over release tables, evaluated on the phone (an embedded query engine over Parquet, for example DataFusion, chosen and recorded); error bars computed automatically from each part's published noise; differences within the noise flagged; weighting to Census figures as a built-in lens, labeled as such; takes pinned to release versions so they're reproducible and forkable.
- **Publishing a take:** its manifest, its text blob, and its labeling when an agent wrote it.
- **Fairness ranking:** people rate whether a take is a fair reading with the same left and right gesture as voting. Those ratings go through the private aggregation `take.md` specifies, and the gallery ranks takes by whether every opinion group rates them fair.
- **`services/gallery`:** an index of published takes, ranking from released ratings, search, forks.
- **Keep two claims apart** everywhere in the UI and in generated captions: "people here think X" versus "the district thinks X". Self-selection is real; the studio should make it visible.

## Tests

Take vectors; a simulator scenario where takes are built on a release, rated, and ranked; reproducibility (re-running a take on its pinned release gives identical output); error bars match the published noise.

## Done when

The studio and gallery boards work against real releases in the simulator, and a take round-trips through publish, fork and re-run.
