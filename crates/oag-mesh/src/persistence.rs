//! Minimal disk persistence for this crate's seven in-memory stores (`bridge::MeshTree`,
//! `corroboration::ClaimCorroboration`, `anonymous_event::AnonymousEventLog`,
//! `membership::MembershipRegistry`, `responder::ResponderAcknowledgmentLog`,
//! and the responder dispatch subscription registry and inbox) -- all of which were, until this
//! file, purely in-memory and lost on every restart (`spec/02`'s and `spec/05`'s own
//! previously-stated "no persistence" gap).
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
//! complete file. Individually atomic files are not enough for a set of them, so a save also
//! writes a commit marker (`commit.json`) recording every file's BLAKE3, and a load verifies it
//! before trusting the set -- see [`verify_commit_marker`]. Not a database: no cross-process
//! locking beyond that, no WAL, no incremental writes -- a save rewrites the entire store every
//! time. Fine for this crate's current scale and the fact that losing any of this state only
//! means re-learning it from the mesh over time, not losing anything irrecoverable; not fine to
//! build on if that stops being true.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

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
    /// The commit marker exists but the set of store files it describes does not match it --
    /// some file is missing, unreadable, or has different bytes. This is a torn write from a
    /// crash between the individual saves, and loading it would silently accept a set whose
    /// stores disagree with each other.
    #[error("inconsistent store set at {path}: {detail}")]
    TornSet { path: String, detail: String },
}

/// The commit marker's filename, written *after* every store file in a save.
pub const COMMIT_MARKER_FILE: &str = "commit.json";

/// Current marker schema version. Bump when the marker's meaning changes in a way an older
/// reader would misinterpret.
const COMMIT_MARKER_VERSION: u32 = 1;

/// One store file recorded in the commit marker: its filename (relative to the store dir) and
/// the BLAKE3 of the exact bytes on disk.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CommitEntry {
    pub file: String,
    pub blake3: String,
}

/// The commit marker: the set of files that make up one consistent snapshot.
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitMarker {
    pub version: u32,
    pub files: Vec<CommitEntry>,
}

/// The result of checking a store directory for a commit marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitState {
    /// No marker. Either a first run (nothing has ever been saved) or a directory written by a
    /// version predating the marker. Load whatever is there, exactly as before -- refusing here
    /// would break every existing deployment on upgrade.
    Legacy,
    /// A marker is present and every file it records matches its recorded hash.
    Consistent,
}

/// BLAKE3 of a file's exact bytes. This is a whole-file integrity check, not a content hash of
/// the parsed value: it is precisely "did the bytes on disk change since the save", which is the
/// only question a crash can make ambiguous.
pub fn hash_file(path: &Path) -> Result<String, PersistenceError> {
    let bytes = std::fs::read(path)
        .map_err(|source| PersistenceError::Read { path: path.display().to_string(), source })?;
    Ok(blake3::hash(&bytes).to_hex().to_string())
}

/// Writes the commit marker describing `entries`, atomically via [`save_json`]. Called *after*
/// every store file in the set has been written, so the marker's presence means "the whole set is
/// on disk". Its absence after a crash means the previous set is still intact and the orphaned
/// partial files are simply ignored.
pub fn write_commit_marker(dir: &Path, entries: Vec<CommitEntry>) -> Result<(), PersistenceError> {
    let marker = CommitMarker { version: COMMIT_MARKER_VERSION, files: entries };
    save_json(&dir.join(COMMIT_MARKER_FILE), &marker)
}

/// Checks `dir` for a commit marker and, if one exists, that every file it records is present and
/// hashes to its recorded value.
///
/// Returns [`CommitState::Legacy`] when there is no marker at all -- deliberately not an error, so
/// a directory written by an older version still loads. Returns [`PersistenceError::TornSet`] when
/// a marker exists but the set does not match it: that is a torn write, and the caller should
/// refuse to load rather than act on stores that disagree with each other.
pub fn verify_commit_marker(dir: &Path) -> Result<CommitState, PersistenceError> {
    let marker_path = dir.join(COMMIT_MARKER_FILE);
    let marker: CommitMarker = match load_json(&marker_path)? {
        Some(marker) => marker,
        None => return Ok(CommitState::Legacy),
    };
    if marker.version != COMMIT_MARKER_VERSION {
        return Err(PersistenceError::TornSet {
            path: marker_path.display().to_string(),
            detail: format!("unsupported marker version {} (expected {COMMIT_MARKER_VERSION})", marker.version),
        });
    }
    for entry in &marker.files {
        let path = dir.join(&entry.file);
        let actual = hash_file(&path).map_err(|source| PersistenceError::TornSet {
            path: marker_path.display().to_string(),
            detail: format!("{} is missing or unreadable: {source}", entry.file),
        })?;
        if actual != entry.blake3 {
            return Err(PersistenceError::TornSet {
                path: marker_path.display().to_string(),
                detail: format!(
                    "{} changed since the save (marker {}, actual {actual})",
                    entry.file, entry.blake3
                ),
            });
        }
    }
    Ok(CommitState::Consistent)
}

/// The seven store filenames, in save order. The last file is not special -- the commit marker
/// written after all of them is what makes the set atomic.
pub const STORE_FILES: [&str; 7] = [
    "bridge_tree.json",
    "claim_corroboration.json",
    "anonymous_events.json",
    "membership_registry.json",
    "responder_acknowledgments.json",
    "responder_subscriptions.json",
    "responder_inbox.json",
];

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

    fn test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oag-mesh-commit-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn save_two_files(dir: &Path) -> Vec<CommitEntry> {
        let a = dir.join("a.json");
        let b = dir.join("b.json");
        save_json(&a, &Example { a: "one".into(), b: 1 }).unwrap();
        save_json(&b, &Example { a: "two".into(), b: 2 }).unwrap();
        vec![
            CommitEntry { file: "a.json".into(), blake3: hash_file(&a).unwrap() },
            CommitEntry { file: "b.json".into(), blake3: hash_file(&b).unwrap() },
        ]
    }

    #[test]
    fn a_directory_with_no_marker_is_legacy_not_an_error() {
        // A first run, or a directory written before markers existed. Both must load the old way;
        // treating the absence of a marker as corruption would break every existing deployment on
        // upgrade.
        let dir = test_dir("legacy");
        save_two_files(&dir);
        assert_eq!(verify_commit_marker(&dir).unwrap(), CommitState::Legacy);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_matching_marker_is_consistent() {
        let dir = test_dir("consistent");
        let entries = save_two_files(&dir);
        write_commit_marker(&dir, entries).unwrap();
        assert_eq!(verify_commit_marker(&dir).unwrap(), CommitState::Consistent);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_deleted_store_file_is_a_torn_set() {
        // The crash window the marker exists to close: every file is individually atomic, so a
        // crash mid-save leaves some stores from the new snapshot and some from the old. Losing
        // one file is the same shape and must be refused rather than loaded.
        let dir = test_dir("deleted");
        let entries = save_two_files(&dir);
        write_commit_marker(&dir, entries.clone()).unwrap();
        std::fs::remove_file(dir.join("b.json")).unwrap();
        let err = verify_commit_marker(&dir).unwrap_err();
        assert!(matches!(err, PersistenceError::TornSet { .. }), "expected TornSet, got {err}");
        assert!(err.to_string().contains("b.json"), "the error should name the missing file: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_modified_store_file_is_a_torn_set() {
        // A torn write can also leave a file present but at its previous snapshot's bytes.
        let dir = test_dir("modified");
        let entries = save_two_files(&dir);
        write_commit_marker(&dir, entries).unwrap();
        save_json(&dir.join("a.json"), &Example { a: "changed".into(), b: 99 }).unwrap();
        let err = verify_commit_marker(&dir).unwrap_err();
        assert!(matches!(err, PersistenceError::TornSet { .. }), "expected TornSet, got {err}");
        assert!(err.to_string().contains("a.json"), "the error should name the changed file: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_corrupt_marker_is_refused_rather_than_ignored() {
        // A marker that cannot be parsed is not the same as no marker: it means a save was
        // interrupted at the very last step, and the set's consistency is unknown.
        let dir = test_dir("corrupt");
        let entries = save_two_files(&dir);
        write_commit_marker(&dir, entries).unwrap();
        std::fs::write(dir.join(COMMIT_MARKER_FILE), b"{ not json").unwrap();
        let err = verify_commit_marker(&dir).unwrap_err();
        assert!(matches!(err, PersistenceError::Parse { .. }), "expected Parse, got {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_unsupported_marker_version_is_refused() {
        let dir = test_dir("version");
        let entries = save_two_files(&dir);
        save_json(
            &dir.join(COMMIT_MARKER_FILE),
            &CommitMarker { version: COMMIT_MARKER_VERSION + 1, files: entries },
        )
        .unwrap();
        let err = verify_commit_marker(&dir).unwrap_err();
        assert!(matches!(err, PersistenceError::TornSet { .. }), "expected TornSet, got {err}");
        assert!(err.to_string().contains("version"), "the error should mention the version: {err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_marker_writing_twice_is_idempotent() {
        let dir = test_dir("twice");
        let entries = save_two_files(&dir);
        write_commit_marker(&dir, entries.clone()).unwrap();
        write_commit_marker(&dir, entries).unwrap();
        assert_eq!(verify_commit_marker(&dir).unwrap(), CommitState::Consistent);
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
