//! Minimal disk persistence for this crate's three in-memory stores (`bridge::MeshTree`,
//! `corroboration::ClaimCorroboration`, `anonymous_event::AnonymousEventLog`) -- all of which
//! were, until this file, purely in-memory and lost on every restart (`spec/02`'s and `spec/05`'s
//! own previously-stated "no persistence" gap).
//!
//! Deliberately simple: one JSON file per store, written on demand by a caller (`MeshState`'s
//! own `save_to_dir`/`load_from_dir`), not automatically on every write. This crate has no
//! opinion on *when* a caller should save -- periodically, on a clean shutdown signal, after
//! every N writes -- that's left to whatever embeds this crate, same as everything else here
//! that stops short of a full deployment story.
//!
//! **What this explicitly is not.** A save is now atomic on Unix -- `save_json` writes a sibling
//! temp file and renames it over the destination, so a crash mid-write leaves the previous file
//! intact and the temp file orphaned, rather than a truncated destination. On Windows the
//! rename does not replace an existing file, so the destination is removed first; that window is
//! not atomic and is the platform's best effort. Each save uses a unique temp name
//! (`<name>.<pid>.<counter>.tmp`), so two processes saving the same file never clobber each
//! other's partial write; the final rename is atomic, so the destination is always one writer's
//! complete file. Not a database: no cross-process locking beyond that, no WAL, no incremental
//! writes -- a save rewrites the entire store every time. Fine for this crate's current scale
//! and the fact that losing any of this state only means re-learning it from the mesh over
//! time, not losing anything irrecoverable; not fine to build on if that stops being true.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::Serialize;

static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A unique sibling temp path for a save: `<name>.<pid>.<counter>.tmp`. Two writers saving the
/// same file never share a temp name, so neither can clobber the other's partial write before the
/// rename. The final rename is atomic, so the destination is always one writer's complete file.
fn tmp_path(path: &Path) -> PathBuf {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("store");
    let n = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    path.with_file_name(format!("{name}.{}.{n}.tmp", std::process::id()))
}

#[derive(Debug, thiserror::Error)]
pub enum PersistenceError {
    #[error("failed to read {path}: {source}")]
    Read { path: String, source: std::io::Error },
    #[error("failed to write {path}: {source}")]
    Write { path: String, source: std::io::Error },
    #[error("failed to parse {path} as JSON: {source}")]
    Parse { path: String, source: serde_json::Error },
    #[error("failed to serialize value for {path}: {source}")]
    Serialize { path: String, source: serde_json::Error },
}

/// Writes `value` to `path` as JSON, overwriting whatever was there. The write goes to a
/// sibling temp file first and is then renamed over the destination -- atomic on Unix, where
/// `rename(2)` replaces the destination in one step. See this module's own doc comment for the
/// Windows caveat and the remaining limits.
pub fn save_json<T: Serialize>(path: &Path, value: &T) -> Result<(), PersistenceError> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|source| PersistenceError::Serialize { path: path.display().to_string(), source })?;
    let tmp = tmp_path(path);
    std::fs::write(&tmp, json)
        .map_err(|source| PersistenceError::Write { path: tmp.display().to_string(), source })?;
    if cfg!(windows) {
        // Windows `rename` does not replace an existing file; remove it first. That window is
        // not atomic -- on Unix the rename above is the whole story.
        let _ = std::fs::remove_file(path);
    }
    std::fs::rename(&tmp, path)
        .map_err(|source| PersistenceError::Write { path: path.display().to_string(), source })?;
    Ok(())
}

/// Reads and parses `path` as JSON. Returns `Ok(None)` if the file doesn't exist yet -- a fresh
/// node's first run, before anything has ever been saved -- rather than treating that as an
/// error.
pub fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, PersistenceError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(PersistenceError::Read { path: path.display().to_string(), source }),
    };
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|source| PersistenceError::Parse { path: path.display().to_string(), source })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct Example {
        a: String,
        b: u32,
    }

    #[test]
    fn save_then_load_round_trips() {
        let dir = std::env::temp_dir().join(format!("oag-mesh-persistence-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("example.json");

        let value = Example { a: "hello".to_string(), b: 42 };
        save_json(&path, &value).unwrap();
        let loaded: Option<Example> = load_json(&path).unwrap();
        assert_eq!(loaded, Some(value));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn save_json_leaves_no_temp_file_behind() {
        let dir = std::env::temp_dir().join(format!("oag-mesh-persistence-test-tmp-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("example.json");

        save_json(&path, &Example { a: "hello".to_string(), b: 42 }).unwrap();
        assert!(path.exists());
        // No `<name>.*.tmp` file is left behind.
        assert!(!std::fs::read_dir(&dir).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".tmp")));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn loading_a_nonexistent_file_returns_none_not_an_error() {
        let path = std::env::temp_dir().join(format!("oag-mesh-persistence-test-missing-{}.json", std::process::id()));
        let loaded: Option<Example> = load_json(&path).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn loading_malformed_json_returns_a_parse_error() {
        let dir = std::env::temp_dir().join(format!("oag-mesh-persistence-test-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.json");
        std::fs::write(&path, b"not valid json").unwrap();

        let result: Result<Option<Example>, PersistenceError> = load_json(&path);
        assert!(matches!(result, Err(PersistenceError::Parse { .. })));

        std::fs::remove_dir_all(&dir).ok();
    }
}
