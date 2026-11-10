//! Onion routing for anonymous-event submission: the reporter wraps the submission in layers,
//! one per relay, so no single relay learns both the reporter and the target.
//!
//! Each relay's X25519 key is derived from its existing Ed25519 identity -- the Ed25519 scalar
//! is a valid clamped X25519 private key, and the Montgomery u-coordinate of the Ed25519
//! verifying key is the X25519 public key -- so no separate key directory is needed. A reporter
//! who knows a relay's Ed25519 public key can compute its X25519 key; a relay computes the same
//! key from its own identity.
//!
//! A layer is ChaCha20-Poly1305 under a key derived from an ephemeral X25519 exchange with the
//! relay's static key. The relay peels its layer with its identity, recovers the next hop and the
//! inner payload, and forwards. The reporter sends the outermost layer to the guard.
//!
//! **What this explicitly is not.** Not traffic-analysis resistance: an observer who can see
//! traffic entering and leaving the mesh can still correlate timing and volume. Not a hidden
//! path: the relays' addresses are not hidden from the network. Not a defense against a global
//! adversary who operates enough relays. See `spec/15-onion-routing.md`.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use oag_crypto::{PeerIdentity, random_bytes_32};
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::anonymous_event::{AnonymousEvent, ProofOfWork};

pub const ONION_KEY_DOMAIN: &[u8] = b"OAG-MESH:ONION:v1:";
pub const ONION_KEY_BYTES: usize = 32;
pub const ONION_NONCE_BYTES: usize = 12;

#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    #[error("hex decoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("expected {expected} bytes, got {actual}")]
    BadLength { expected: usize, actual: usize },
    #[error("key derivation failed")]
    KeyDerivation,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed")]
    Decrypt,
    #[error("serialization failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("the relay path is empty")]
    EmptyPath,
}

/// One layer of the onion, as it travels between relays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    /// Hex-encoded X25519 ephemeral public key, used by the relay to derive the shared secret.
    pub ephemeral_public_key: String,
    /// Hex-encoded 12-byte ChaCha20-Poly1305 nonce.
    pub nonce: String,
    /// Hex-encoded ciphertext of the inner payload.
    pub ciphertext: String,
}

/// What a relay finds after peeling its layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionInner {
    /// Where to forward the payload: the next relay's address, or the target's.
    pub next_hop: String,
    pub payload: OnionPayload,
}

/// The payload a relay forwards: either another onion layer, or the final submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "body")]
pub enum OnionPayload {
    Layer(Box<OnionLayer>),
    Submission { event: AnonymousEvent, pow: ProofOfWork },
}

/// The X25519 static secret corresponding to a peer's Ed25519 identity.
pub fn x25519_static_secret(identity: &PeerIdentity) -> StaticSecret {
    StaticSecret::from(identity.signing_key().to_scalar_bytes())
}

/// The X25519 public key corresponding to a peer's Ed25519 identity -- the Montgomery
/// u-coordinate of the Ed25519 verifying key.
pub fn x25519_public_key(identity: &PeerIdentity) -> PublicKey {
    PublicKey::from(identity.verifying_key().to_montgomery().to_bytes())
}

fn derive_key(shared_secret: &[u8]) -> [u8; ONION_KEY_BYTES] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ONION_KEY_DOMAIN);
    hasher.update(shared_secret);
    *hasher.finalize().as_bytes()
}

fn random_nonce() -> [u8; ONION_NONCE_BYTES] {
    let bytes = random_bytes_32();
    let mut nonce = [0u8; ONION_NONCE_BYTES];
    nonce.copy_from_slice(&bytes[..ONION_NONCE_BYTES]);
    nonce
}

fn decode_hex<const N: usize>(s: &str) -> Result<[u8; N], OnionError> {
    let bytes = hex::decode(s)?;
    if bytes.len() != N {
        return Err(OnionError::BadLength { expected: N, actual: bytes.len() });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Wraps `inner_bytes` in one layer for the relay with `relay_public`.
fn wrap_layer(relay_public: &PublicKey, inner_bytes: &[u8]) -> Result<OnionLayer, OnionError> {
    let ephemeral = StaticSecret::from(random_bytes_32());
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(relay_public);
    let key = derive_key(shared.as_bytes());
    let nonce = random_nonce();
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| OnionError::KeyDerivation)?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: inner_bytes, aad: &[] })
        .map_err(|_| OnionError::Encrypt)?;
    Ok(OnionLayer {
        ephemeral_public_key: hex::encode(ephemeral_public.to_bytes()),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ciphertext),
    })
}

/// Peels one layer with the relay's own identity, recovering the next hop and payload.
pub fn peel_layer(layer: &OnionLayer, identity: &PeerIdentity) -> Result<OnionInner, OnionError> {
    let ephemeral_public = PublicKey::from(decode_hex::<ONION_KEY_BYTES>(&layer.ephemeral_public_key)?);
    let nonce_bytes = decode_hex::<ONION_NONCE_BYTES>(&layer.nonce)?;
    let ciphertext = hex::decode(&layer.ciphertext)?;

    let static_secret = x25519_static_secret(identity);
    let shared = static_secret.diffie_hellman(&ephemeral_public);
    let key = derive_key(shared.as_bytes());
    let cipher = ChaCha20Poly1305::new_from_slice(&key).map_err(|_| OnionError::KeyDerivation)?;
    let inner_bytes = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), Payload { msg: &ciphertext, aad: &[] })
        .map_err(|_| OnionError::Decrypt)?;
    let inner: OnionInner = serde_json::from_slice(&inner_bytes)?;
    Ok(inner)
}

/// Builds the outermost layer to send to the guard, for a path of relays (guard first) and a
/// final target. `relay_keys` must align with `path`.
pub fn build_onion(
    path: &[String],
    target: &str,
    event: &AnonymousEvent,
    pow: ProofOfWork,
    relay_keys: &[PublicKey],
) -> Result<OnionLayer, OnionError> {
    if path.is_empty() {
        return Err(OnionError::EmptyPath);
    }
    if relay_keys.len() != path.len() {
        return Err(OnionError::BadLength { expected: path.len(), actual: relay_keys.len() });
    }

    let mut payload = OnionPayload::Submission { event: event.clone(), pow };
    let mut next_hop = target.to_string();

    for (relay_public, address) in relay_keys.iter().zip(path.iter()).rev() {
        let inner = OnionInner { next_hop, payload };
        let inner_bytes = serde_json::to_vec(&inner)?;
        let layer = wrap_layer(relay_public, &inner_bytes)?;
        payload = OnionPayload::Layer(Box::new(layer));
        next_hop = address.clone();
    }

    match payload {
        OnionPayload::Layer(layer) => Ok(*layer),
        OnionPayload::Submission { .. } => unreachable!("the loop always wraps at least once"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anonymous_event::{CoarseLocation, EventKind, Severity};
    use oag_crypto::PeerIdentity;

    fn event(nonce: &str) -> AnonymousEvent {
        AnonymousEvent {
            event_id: "evt-1".to_string(),
            kind: EventKind::HazardObserved,
            severity: Severity::High,
            observed_at: 1_700_000_400,
            location: CoarseLocation("9q8yy".to_string()),
            corroboration_nonce: nonce.to_string(),
        }
    }

    #[test]
    fn the_x25519_public_key_is_consistent_with_the_static_secret() {
        let identity = PeerIdentity::generate();
        let secret = x25519_static_secret(&identity);
        let derived = PublicKey::from(&secret);
        assert_eq!(derived.to_bytes(), x25519_public_key(&identity).to_bytes());
    }

    #[test]
    fn an_onion_round_trips_through_a_path() {
        let reporter_event = event("onion-round-trip");
        let pow = ProofOfWork { nonce: 1 };
        let path = ["http://relay-1".to_string(), "http://relay-2".to_string()];
        let identities = [PeerIdentity::generate(), PeerIdentity::generate()];
        let relay_keys: Vec<PublicKey> = identities.iter().map(x25519_public_key).collect();

        let guard_layer = build_onion(&path, "http://target", &reporter_event, pow, &relay_keys).unwrap();

        // The guard peels, finds the second relay, and forwards the inner layer.
        let inner_1 = peel_layer(&guard_layer, &identities[0]).unwrap();
        assert_eq!(inner_1.next_hop, "http://relay-2");
        let layer_2 = match inner_1.payload {
            OnionPayload::Layer(layer) => *layer,
            OnionPayload::Submission { .. } => panic!("expected a layer"),
        };

        // The exit peels, finds the target, and recovers the submission.
        let inner_2 = peel_layer(&layer_2, &identities[1]).unwrap();
        assert_eq!(inner_2.next_hop, "http://target");
        match inner_2.payload {
            OnionPayload::Submission { event, pow } => {
                assert_eq!(event.corroboration_nonce, "onion-round-trip");
                assert_eq!(pow, ProofOfWork { nonce: 1 });
            }
            OnionPayload::Layer(_) => panic!("expected a submission"),
        }
    }

    #[test]
    fn an_empty_path_and_a_mismatched_key_list_are_rejected() {
        let identities = [PeerIdentity::generate(), PeerIdentity::generate()];
        let one_key = vec![x25519_public_key(&identities[0])];
        let two_keys = vec![x25519_public_key(&identities[0]), x25519_public_key(&identities[1])];

        assert!(matches!(
            build_onion(&[], "http://target", &event("empty"), ProofOfWork { nonce: 1 }, &one_key),
            Err(OnionError::EmptyPath)
        ));
        // Two keys for a one-hop path is a caller bug, not something to silently truncate.
        assert!(matches!(
            build_onion(
                &["http://relay-1".to_string()],
                "http://target",
                &event("mismatch"),
                ProofOfWork { nonce: 1 },
                &two_keys,
            ),
            Err(OnionError::BadLength { expected: 1, actual: 2 })
        ));
    }

    #[test]
    fn a_malformed_layer_is_rejected_at_every_field() {
        let identities = [PeerIdentity::generate()];
        let relay_keys = vec![x25519_public_key(&identities[0])];
        let layer = build_onion(
            &["http://relay-1".to_string()],
            "http://target",
            &event("malformed"),
            ProofOfWork { nonce: 1 },
            &relay_keys,
        )
        .unwrap();

        // Bad hex in the ephemeral key.
        let mut bad_hex = layer.clone();
        bad_hex.ephemeral_public_key = "zz".to_string();
        assert!(matches!(peel_layer(&bad_hex, &identities[0]), Err(OnionError::Hex(_))));

        // A nonce of the wrong length is a length error, not a panic.
        let mut bad_nonce = layer.clone();
        bad_nonce.nonce = hex::encode([0u8; 8]);
        assert!(matches!(
            peel_layer(&bad_nonce, &identities[0]),
            Err(OnionError::BadLength { expected: ONION_NONCE_BYTES, actual: 8 })
        ));

        // A truncated ciphertext fails authentication, not deserialization -- the AEAD tag
        // is checked before the inner payload is ever parsed.
        let mut bad_ciphertext = layer.clone();
        bad_ciphertext.ciphertext = hex::encode(&[0u8; 8]);
        assert!(matches!(
            peel_layer(&bad_ciphertext, &identities[0]),
            Err(OnionError::Decrypt)
        ));
    }

    #[test]
    fn a_wrong_identity_cannot_peel_the_layer() {
        let identities = [PeerIdentity::generate(), PeerIdentity::generate()];
        let relay_keys = vec![x25519_public_key(&identities[0])];
        let layer = build_onion(
            &["http://relay-1".to_string()],
            "http://target",
            &event("wrong-identity"),
            ProofOfWork { nonce: 1 },
            &relay_keys,
        )
        .unwrap();
        assert!(peel_layer(&layer, &identities[1]).is_err());
    }
}
