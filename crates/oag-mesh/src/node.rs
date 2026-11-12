//! Wiring the mesh into a real `oag` node.
//!
//! The mesh does not keep its own copy of the peer list or the node's identity: it reads them from
//! `oag`'s storage -- the layer below -- and builds its state from what it finds. That is the
//! connection this layer exists to provide, and until this module nothing in either repository
//! made it: `MeshState::load_from_dir` and `save_to_dir` had no caller anywhere, so the
//! persistence layer was correct and tested but unreachable in production.
//!
//! **What this explicitly is not.** Not a writer to the base project's own state. The adapter only
//! reads `identity.key` and the peer tables; the base project's writers (`oag-sync`) remain the
//! only writers of those. The mesh's *own* stores live under `<data-dir>/mesh/` and only this
//! crate writes them. Not a migration: `open_pool` runs `oag`'s embedded migrations, which are
//! idempotent, but this crate adds none of its own.

use std::path::Path;

use oag_crypto::PeerIdentity;
use oag_storage::open_pool;
use oag_storage::repo::peers;

use crate::transport::MeshState;

const IDENTITY_FILE: &str = "identity.key";
const DATABASE_FILE: &str = "oag.sqlite";
const MESH_DIR: &str = "mesh";

#[derive(Debug, thiserror::Error)]
pub enum MeshNodeError {
    #[error("reading the node identity: {0}")]
    Identity(#[from] std::io::Error),
    #[error("storage error: {0}")]
    Storage(#[from] oag_storage::StorageError),
    #[error("sqlx error: {0}")]
    Sqlx(String),
    #[error("persistence error: {0}")]
    Persistence(#[from] crate::persistence::PersistenceError),
    #[error("filesystem error: {0}")]
    // No `#[from]`: `Identity` already provides `From<std::io::Error>`, and a second blanket
    // conversion from the same source would be ambiguous.
    Fs(std::io::Error),
}

/// An `oag` data directory, read as a mesh node's starting state.
#[derive(Debug)]
pub struct MeshNodeAdapter;

impl MeshNodeAdapter {
    /// Loads a `MeshState` from an existing `oag` deployment's data directory.
    ///
    /// The identity comes from `<data-dir>/identity.key`, generated if absent -- the same file
    /// `oag` itself uses, so a mesh node and its base peer are the same cryptographic identity
    /// rather than two that have to be kept in step. The peers come from the base peer's own peer
    /// list, which is what the mesh federates. The mesh's five stores come from
    /// `<data-dir>/mesh/`, empty on a first run.
    ///
    /// Sharing the base peer's identity is a deliberate choice: a `BridgeDeclaration` signed by
    /// this node is then attributable to a peer that already exists, and the mesh's peer id matches
    /// the id the base project already uses for the same node.
    pub async fn load(data_dir: &Path) -> Result<MeshState, MeshNodeError> {
        let identity = PeerIdentity::load_or_generate(&data_dir.join(IDENTITY_FILE))?;
        let peers = Self::dialable_peers(&data_dir.join(DATABASE_FILE)).await?;
        let state = MeshState::load_from_dir(identity, peers, &data_dir.join(MESH_DIR))?;
        Ok(state)
    }

    /// The base peer's peer list, as addresses the mesh's HTTP transport can dial.
    ///
    /// The base project stores a peer's address without a scheme and its own sync client prepends
    /// `http://` (`oag-sync`'s `client.rs`). The mesh dials a full URL, so the same convention is
    /// applied here rather than assuming the stored form is already dialable.
    async fn dialable_peers(database: &Path) -> Result<Vec<String>, MeshNodeError> {
        let pool = open_pool(database).await?;
        let mut conn = pool.acquire().await.map_err(|e| MeshNodeError::Sqlx(e.to_string()))?;
        let peer_rows = peers::list_peers(&mut conn).await?;
        let mut addresses = Vec::new();
        for peer in peer_rows {
            if let Some(address) = peers::list_addresses(&mut conn, &peer.peer_id)
                .await?
                .into_iter()
                .next()
            {
                addresses.push(dial_address(&address));
            }
        }
        Ok(addresses)
    }

    /// Saves the mesh's own stores under `<data-dir>/mesh/`.
    ///
    /// The base project's files are untouched. This is the write half of `load`, and the reason the
    /// persistence layer has a caller: a mesh node stood up next to an existing peer now keeps its
    /// own state across restarts.
    pub fn save(state: &MeshState, data_dir: &Path) -> Result<(), MeshNodeError> {
        let mesh_dir = data_dir.join(MESH_DIR);
        // `save_to_dir` writes sibling temp files and renames them, so the directory has to exist
        // first. This adapter owns that directory, so it creates it rather than making every
        // caller remember to.
        std::fs::create_dir_all(&mesh_dir).map_err(MeshNodeError::Fs)?;
        state.save_to_dir(&mesh_dir)?;
        Ok(())
    }
}

/// Prepends `http://` to a scheme-less address, leaving an explicit scheme alone.
fn dial_address(address: &str) -> String {
    if address.starts_with("http://") || address.starts_with("https://") {
        address.to_string()
    } else {
        format!("http://{address}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_data_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "oag-mesh-node-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[tokio::test]
    async fn the_adapter_loads_the_identity_and_peers_from_an_oag_data_dir() {
        let dir = temp_data_dir("load");
        let identity = PeerIdentity::generate();
        identity.save(&dir.join(IDENTITY_FILE)).unwrap();

        // A real base-project database with one peer and one address.
        let pool = open_pool(&dir.join(DATABASE_FILE)).await.unwrap();
        let mut conn = pool.acquire().await.unwrap();
        peers::upsert_peer(&mut conn, &[2u8; 32], &[3u8; 32], None, 0).await.unwrap();
        peers::add_address(&mut conn, &[2u8; 32], "127.0.0.1:9000").await.unwrap();
        drop(conn);
        drop(pool);

        let state = MeshNodeAdapter::load(&dir).await.unwrap();
        assert_eq!(
            state.peers.as_slice(),
            &["http://127.0.0.1:9000".to_string()],
            "a scheme-less base-project address must become a dialable URL"
        );
        assert!(
            state.identity.verifying_key() == identity.verifying_key(),
            "the mesh node must share the base peer's identity rather than mint a second one"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn an_address_that_already_has_a_scheme_is_left_alone() {
        assert_eq!(dial_address("http://a.example"), "http://a.example");
        assert_eq!(dial_address("https://a.example"), "https://a.example");
        assert_eq!(dial_address("a.example:9000"), "http://a.example:9000");
    }

    #[tokio::test]
    async fn save_then_load_keeps_the_mesh_state_and_leaves_the_base_files() {
        let dir = temp_data_dir("round-trip");
        let identity = PeerIdentity::generate();
        identity.save(&dir.join(IDENTITY_FILE)).unwrap();
        // A base database, so `load` has something to read.
        let pool = open_pool(&dir.join(DATABASE_FILE)).await.unwrap();
        drop(pool);

        let loaded = MeshNodeAdapter::load(&dir).await.unwrap();
        MeshNodeAdapter::save(&loaded, &dir).unwrap();

        // The mesh's own stores are on disk under the data directory.
        assert!(dir.join(MESH_DIR).join("commit.json").exists());

        // And a second load sees the same peers and identity.
        let again = MeshNodeAdapter::load(&dir).await.unwrap();
        assert_eq!(again.peers, loaded.peers);
        assert!(again.identity.verifying_key() == loaded.identity.verifying_key());

        // The base project's files are still there and were not replaced.
        assert!(dir.join(IDENTITY_FILE).exists());
        assert!(dir.join(DATABASE_FILE).exists());

        std::fs::remove_dir_all(&dir).ok();
    }
}
