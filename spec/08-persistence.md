# Persistence

**Source**: `crates/oag-mesh/src/persistence.rs`, plus `snapshot`/`from_snapshot` on
`bridge::MeshTree`, `corroboration::ClaimCorroboration`, `membership::MembershipRegistry`, and
`responder::ResponderAcknowledgmentLog`, a direct `Serialize`/`Deserialize` derive on
`anonymous_event::AnonymousEventLog`, and `transport::MeshState::save_to_dir`/`load_from_dir`.

Closes the "no persistence" gap `spec/02-cluster-nesting.md` and
`spec/05-federated-corroboration.md` each previously listed: the in-memory stores were lost on
every restart, rebuilt from scratch only by whatever got pushed to a node again after it came
back up. The original five stores are now seven: `spec/14-responder-dispatch.md`'s blinded
subscription registry and inbox are persisted too.

## The mechanism

One JSON file per store, written to an operator-chosen directory: `bridge_tree.json`,
`claim_corroboration.json`, `anonymous_events.json`, `membership_registry.json`,
`responder_acknowledgments.json`, `responder_subscriptions.json`, and `responder_inbox.json`.
`MeshState::save_to_dir(dir)` writes all seven; `MeshState::load_from_dir(identity, peers, dir)`
builds a fresh `MeshState` by reading back whichever of the seven files exist, starting empty
for any that don't (a brand-new node's first run).

`AnonymousEvent` carries no `PeerId` at all (identity-stripped by design -- see
`spec/03-anonymous-event-rfc.md`), so `AnonymousEventLog` derives `Serialize`/`Deserialize`
directly; its `HashMap<String, Vec<AnonymousEvent>>` is already fully serializable. `MeshTree`,
`ClaimCorroboration`, `MembershipRegistry`, and `ResponderAcknowledgmentLog` all key internal
state in part by `PeerId`, which has no `Serialize`/`Deserialize` of its own (it's the base
project's type, reused via git dependency, never modified here) -- so each exposes a
`snapshot()`/`from_snapshot()` pair (`BridgeEdgeSnapshot`, `ClaimSnapshot`/
`RecordedReportSnapshot`, `MembershipSnapshot`, `ResponderAcknowledgmentSnapshot`/
`RecordedAcknowledgmentSnapshot`) that round-trips a `PeerId` through its `Display`/`FromStr`
string form, the same convention every signed message in this crate already uses for a
`peer_id` field. A peer id string that fails to parse on load is dropped with a
`tracing::warn!` rather than failing the whole load.

## What this explicitly is not

- **Not automatic.** Nothing in this crate calls `save_to_dir` on its own -- not after every
  write, not on a timer, not on shutdown. A caller embedding this crate decides when to save;
  that decision depends on deployment specifics (how much state loss on an unclean restart is
  acceptable) this crate has no opinion on.

  **There is now a caller-side adapter, though it is still not automatic.**
  `node::MeshNodeAdapter` (`crates/oag-mesh/src/node.rs`) builds a `MeshState` from an existing
  `oag` deployment -- identity from `<data-dir>/identity.key`, peers from the base peer's own peer
  tables, mesh stores from `<data-dir>/mesh/` -- and saves it back. The caller still chooses when
  to call `save`; what changed is that the persistence layer is now reachable from a real
  deployment rather than only from tests. Before the adapter, no code in either repository called
  `save_to_dir` or `load_from_dir`, so the commit marker and torn-set refusal had never run
  outside a test.

  The adapter shares the base peer's identity rather than minting a second one: a
  `BridgeDeclaration` signed by this node is then attributable to a peer that already exists, and
  the mesh's peer id matches the id the base project already uses for that node. It reads the base
  project's files and never writes them; the mesh's own stores live under `mesh/`.
- **Atomic on Unix, best-effort on Windows, but not crash-proof.** `persistence::save_json`
  writes a sibling temp file and renames it over the destination. On Unix, `rename(2)` is
  atomic: a crash mid-write leaves the previous file intact and the temp file orphaned, rather
  than a truncated destination. On Windows, `rename` does not replace an existing file, so the
  destination is removed first -- that window is not atomic, and is the platform's best effort.
  There is no fsync, so a power loss could still lose the rename; no write-ahead log.
- **The seven stores commit as a set, via a marker written last.** Each file being individually
  atomic is not enough: a crash between the individual saves leaves a *torn* set, with some stores
  from the new snapshot and some from the old, and every file still parses -- nothing downstream
  could tell they disagreed. `save_to_dir` now writes all seven files, hashes each one's exact
  bytes, and then writes `commit.json` recording `{version, files: [{file, blake3}]}`. The marker
  is written last, so its presence means the whole set is on disk. `load_from_dir` verifies it
  first: every recorded file must exist and hash to its recorded value, or the load is refused
  with `PersistenceError::TornSet` rather than acting on a set that disagrees with itself. A
  marker that cannot be parsed is treated the same way -- it means the save was interrupted at
  the last step and the set's consistency is unknown. See `OPEN_QUESTIONS.md`'s cross-store
  consistency entry for the design and the one remaining gap.
- **A directory with no marker still loads exactly as before.** This is deliberate backward
  compatibility, not an oversight: an existing deployment upgrades, its directory has seven store
  files and no `commit.json`, and refusing to load would strand every one of those nodes' state.
  Absence of a marker means "written by an older version, or a first run" and is not an error.
  Only a marker that is *present and contradicts the files* is refused.
- **Not a database.** Each save uses a unique temp name (`<name>.<pid>.<counter>.tmp`), so two
  processes saving the same file never clobber each other's partial write, and the final rename
  is atomic -- but there is no cross-process locking beyond that, and no incremental writes:
  every save rewrites the entire store from scratch, which is fine at this crate's current scale
  and becomes a real cost long before any of the other gaps in this crate do.
- **No migration/versioning.** A snapshot's shape changes if `BridgeEdgeSnapshot`/`ClaimSnapshot`
  ever change; there's no `schema_version` field and no migrate-or-shim path like the base
  project's own (`future_legacy_compatibility_and_versioning.md` memory there) -- loading an
  old-shaped file after a breaking change would just fail to parse.

## Tests

`crates/oag-mesh/src/persistence.rs` (11 unit tests): save then load round-trips a value exactly;
loading a file that doesn't exist returns `None`, not an error; loading malformed JSON returns a
`PersistenceError::Parse`; and a save leaves no `.tmp` file behind (the rename consumed it),
  using a unique per-save temp name; plus the commit marker's own paths -- a directory with no
  marker is `Legacy` (not an error), a matching marker is `Consistent`, a deleted store file, a
  modified store file, a corrupt marker, and an unsupported marker version are all refused, and
  writing a marker twice is idempotent. `crates/oag-mesh/src/membership.rs` adds 1 more:
`MembershipRegistry::snapshot` round-trips through `from_snapshot` directly.
`crates/oag-mesh/src/responder.rs` adds 1 more: `ResponderAcknowledgmentLog::snapshot`
round-trips through `from_snapshot` directly. `crates/oag-mesh/src/transport.rs` adds 3 more:
`save_to_dir` then `load_from_dir` round-trips one real entry in each of the five original
stores (a `BridgeDeclaration`, a `ClaimReport`, an `AnonymousEvent`, a `MembershipAttestation`,
and a `ResponderAcknowledgment`); the same round-trip covers the dispatch subscription registry
and inbox (`spec/14`); `load_from_dir` against a directory that doesn't exist yet starts with all
seven stores empty rather than erroring; a fresh `save_to_dir` writes a marker that still verifies;
`load_from_dir` refuses a torn set rather than acting on it; and it still accepts a directory
written before markers existed.
