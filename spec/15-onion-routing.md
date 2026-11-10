# Onion Routing

**Source**: `crates/oag-mesh/src/onion.rs`, `crates/oag-mesh/src/transport.rs`
(`/oag-mesh/v1/onion-key`, `/oag-mesh/v1/onion`).

A multi-hop anonymity layer for anonymous-event submission: the reporter wraps the submission in
layers, one per relay, so no single relay learns both the reporter and the target.

## The mechanism

Each relay's X25519 key is derived from its existing Ed25519 identity:

- private: the Ed25519 signing key's scalar (already clamped), as an X25519 `StaticSecret`;
- public: the Montgomery u-coordinate of the Ed25519 verifying key.

So no separate key directory is needed -- a reporter who knows a relay's Ed25519 public key can
compute its X25519 key, and `GET /oag-mesh/v1/onion-key` publishes it for relays whose Ed25519 key
the reporter does not already hold.

A path is `[R1, R2, ..., Rn]` (guard first, exit last) plus a final target. The reporter builds
the onion from the inside out:

1. The innermost payload is the submission.
2. For each hop from exit to guard, the reporter generates an ephemeral X25519 key, derives a
   shared secret with that relay's static key, and encrypts the current payload with
   ChaCha20-Poly1305 under a blake3-derived key.
3. The outermost layer is sent to the guard. Each relay peels its layer, learns the next hop and
   the inner payload, and forwards. The exit relay recovers the submission and forwards it to the
   target's direct endpoint.

No single relay sees both the reporter and the target: the guard sees the reporter and R2; the
exit sees R(n-1) and the target; a middle relay sees only its neighbours.

## What this explicitly is not

- **Not traffic-analysis resistance.** An observer who can see traffic entering and leaving the
  mesh can still correlate timing and volume. This is the hard, unsolved part -- the base
  project's `spec/22-future-work.md` calls it "never ending morphing encryption."
- **Not a hidden path.** The relays' addresses are not hidden from the network; a relay knows its
  immediate neighbours. Only the end-to-end association is hidden.
- **Not a defense against a global adversary.** If one operator runs enough relays, it can
  correlate entry and exit.
- **Not a substitute for end-to-end encryption.** The exit relay sees the submission in
  plaintext (it must, to forward it). The reporter should not put identifying information in the
  payload -- the payload is already identity-stripped by `spec/03`.
- **Not authenticated at the relay.** A relay that receives a layer it cannot peel rejects it
  with `400`; there is no proof-of-work on the onion itself. The escalating proof-of-work is
  still enforced by the target when it records the submission.
- **Node-local, no auth** -- same posture as every other endpoint here. The `/oag-mesh/v1/onion`
  endpoint accepts any layer; a relay that cannot peel it rejects it.
- **Volume-bounded, not authenticated.** This endpoint is the one in this crate that makes the node
  send traffic to an address *chosen by the caller*: the peeled `next_hop` is forwarded to, whether
  it is another relay or the final target. That is inherent to the feature -- an exit relay must be
  able to reach an arbitrary target -- but without a bound it also makes the relay a constrained
  proxy for directing anonymous-event pushes at third parties. A node-wide token bucket
  (`ONION_RATE_LIMIT_CAPACITY`/`ONION_RATE_LIMIT_PER_SEC`, 16 at 0.5/s) bounds the volume. It does
  **not** authenticate anyone, and it does **not** make the relay an open proxy: the payload is
  limited to an identity-stripped event plus proof-of-work, or one more layer, and the target still
  enforces its own escalating proof-of-work. It is a bound on an intentional capability, not a
  permission system.

## Tests

`crates/oag-mesh/src/onion.rs` adds 3 unit tests: the X25519 public key derived from an Ed25519
identity matches the one derived from the corresponding static secret; a two-hop onion round-trips
through both identities and recovers the submission at the target; a wrong identity cannot peel
the layer. `crates/oag-mesh/src/transport.rs` adds 2 integration tests over real HTTP: an onion
path delivers the event to the target only, with neither relay's log recording it; and a relay
rejects a layer built for a different relay's key with `400`.
