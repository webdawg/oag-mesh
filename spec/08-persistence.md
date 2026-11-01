# Persistence

**Source**: `crates/oag-mesh/src/persistence.rs`, plus `snapshot`/`from_snapshot` on
`bridge::MeshTree`, `corroboration::ClaimCorroboration`, and `membership::MembershipRegistry`, a
direct `Serialize`/`Deserialize` derive on `anonymous_event::AnonymousEventLog`, and
`transport::MeshState::save_to_dir`/`load_from_dir`.

Closes the "no persistence" gap `spec/02-cluster-nesting.md` and
`spec/05-federated-corroboration.md` each previously listed: all four in-memory stores were
lost on every restart, rebuilt from scratch only by whatever got pushed to a node again after it
came back up.

## The mechanism

One JSON file per store, written to an operator-chosen directory: `bridge_tree.json`,
`claim_corroboration.json`, `anonymous_events.json`, `membership_registry.json`.
`MeshState::save_to_dir(dir)` writes all four; `MeshState::load_from_dir(identity, peers, dir)`
builds a fresh `MeshState` by reading back whichever of the four files exist, starting empty for
any that don't (a brand-new node's first run).

`AnonymousEvent` carries no `PeerId` at all (identity-stripped by design -- see
`spec/03-anonymous-event-rfc.md`), so `AnonymousEventLog` derives `Serialize`/`Deserialize`
directly; its `HashMap<String, Vec<AnonymousEvent>>` is already fully serializable. `MeshTree`,
`ClaimCorroboration`, and `MembershipRegistry` all key internal state in part by `PeerId`, which
has no `Serialize`/`Deserialize` of its own (it's the base project's type, reused via git
dependency, never modified here) -- so each exposes a `snapshot()`/`from_snapshot()` pair
(`BridgeEdgeSnapshot`, `ClaimSnapshot`/`RecordedReportSnapshot`, `MembershipSnapshot`) that
round-trips a `PeerId` through its `Display`/`FromStr` string form, the same convention every
signed message in this crate already uses for a `peer_id` field. A peer id string that fails to
parse on load is dropped with a `tracing::warn!` rather than failing the whole load.

## What this explicitly is not

- **Not automatic.** Nothing in this crate calls `save_to_dir` on its own -- not after every
  write, not on a timer, not on shutdown. A caller embedding this crate decides when to save;
  that decision depends on deployment specifics (how much state loss on an unclean restart is
  acceptable) this crate has no opinion on.
- **Not atomic or crash-safe.** `persistence::save_json` writes the target file directly, in
  place. A crash mid-write can leave a truncated or partially-written file behind, and the next
  load would then either fail to parse (a clear `PersistenceError::Parse`) or, if the crash
  happened to land after a complete-looking but stale write, silently load older state than the
  caller expected. No temp-file-plus-rename, no fsync, no write-ahead log.
- **Not a database.** No concurrent-writer safety beyond whatever `MeshState`'s own `RwLock`s
  already provide for in-memory access, no incremental writes -- every save rewrites the entire
  store from scratch, which is fine at this crate's current scale and becomes a real cost long
  before any of the other gaps in this crate do.
- **No migration/versioning.** A snapshot's shape changes if `BridgeEdgeSnapshot`/`ClaimSnapshot`
  ever change; there's no `schema_version` field and no migrate-or-shim path like the base
  project's own (`future_legacy_compatibility_and_versioning.md` memory there) -- loading an
  old-shaped file after a breaking change would just fail to parse.

## Tests

`crates/oag-mesh/src/persistence.rs` (3 unit tests): save then load round-trips a value exactly;
loading a file that doesn't exist returns `None`, not an error; loading malformed JSON returns a
`PersistenceError::Parse`. `crates/oag-mesh/src/membership.rs` adds 1 more:
`MembershipRegistry::snapshot` round-trips through `from_snapshot` directly.
`crates/oag-mesh/src/transport.rs` adds 2 more: `save_to_dir` then `load_from_dir` round-trips
one real entry in each of the four stores (a `BridgeDeclaration`, a `ClaimReport`, an
`AnonymousEvent`, and a `MembershipAttestation`, each with valid proof-of-work); `load_from_dir`
against a directory that doesn't exist yet starts with all four stores empty rather than
erroring.
