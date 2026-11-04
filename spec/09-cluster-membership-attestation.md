# Cluster Membership Attestation

**Source**: `crates/oag-mesh/src/membership.rs`, `crates/oag-mesh/src/transport.rs`
(`/oag-mesh/v1/membership-attestation`).

Closes the second half of a gap `spec/02-cluster-nesting.md`'s `MeshTree::is_attested_base_cluster`
and `spec/05-federated-corroboration.md`'s `best_corroborated_value_cross_checked` both named
explicitly in their own doc comments: a `BridgeDeclaration` only ever attests that a cluster
*name* is nested under some mesh-group, signed by whichever peer felt like asserting that -- it
never records which peers actually belong to the cluster. Confirming a `ClaimReport`'s claimed
`reporter_cluster` name is real (spec/02's job) is not the same as confirming the reporting peer
has any actual standing in it. This file is the new kind of signed fact both of those specs said
closing that fully would need.

## The mechanism

Any peer (the "attester") can sign a `MembershipAttestation`: "I attest that `subject_peer_id` is
a genuine member of `cluster`." Signed with the attester's own `oag_crypto::PeerIdentity`, under
this crate's own domain string (`OAG-MESH:MEMBERSHIP_ATTESTATION:v1:`). The subject does not sign
or otherwise participate in producing the attestation -- it is a claim made *about* a peer, not
one it consents to, the same way a reference is written about someone rather than by them.
`verify` rejects a self-attestation (`attester_peer_id == subject_peer_id`) outright: a peer
vouching for its own membership is exactly the bare self-assertion `[cluster].name` already is,
and would let a single identity "corroborate" itself for free, defeating the entire point of
requiring *other* members to vouch.

Verification checks the same three things every signed message in this family does -- the
`(attester_peer_id, attester_public_key)` pairing, the Ed25519 signature, and timestamp freshness
(`MAX_CLOCK_SKEW_SECONDS = 300`) -- plus the self-attestation check above. It does **not** check
whether the attester itself has any real standing in `cluster` -- see "What this explicitly is not
(yet)" below.

## Corroboration

`MembershipRegistry` collects verified attestations in memory, keyed by `(cluster,
subject_peer_id)`, and counts **distinct attesting peers** -- the same `HashSet<PeerId>`-per-fact
shape `bridge::MeshTree` uses for edges, for the identical reason: the same attester re-asserting
the same fact must not inflate corroboration, only genuinely distinct attesters agreeing
independently should. `is_attested_member(cluster, subject_peer_id, min_corroboration)` is the
query a caller actually wants: does at least `min_corroboration` distinct peers vouch for this
membership?

## Anti-sybil resistance

Same gap, same shape, as every other mechanism in this crate: signature verification alone doesn't
bound how many fresh `PeerIdentity`s one actor can mint to independently "attest" the same
`(cluster, subject_peer_id)` fact, inflating the distinct-attester count for free -- which would
let an attacker manufacture apparent membership standing for a fabricated or sybil subject peer
just as cheaply as the cluster-name cross-check it exists to strengthen.

`MembershipProofOfWork` mirrors `bridge::BridgeProofOfWork`'s and
`corroboration::ClaimReportProofOfWork`'s blake3-based, Hashcash-style leading-zero-bit search,
bound to one `(attester_peer_id, subject_peer_id, cluster)` combination. The difficulty
`MembershipRegistry::required_difficulty_bits` requires is keyed to distinct-attester count on
that pair -- the exact resource `is_attested_member` counts:

- **Free (`0` bits) if `attester_peer_id` has already attested this exact fact.** Re-attesting it
  (e.g. with a fresher timestamp) can't increase the distinct-attester count, so there's nothing
  to tax.
- **Otherwise, `BASE_MEMBERSHIP_DIFFICULTY_BITS` plus `MEMBERSHIP_DIFFICULTY_STEP_BITS` for every
  distinct attester already vouching for this pair.** The first attester pays the base cost; the
  fifth pays real, escalating work.

Same caveat as every other proof-of-work in this crate, stated plainly: this raises the cost of
fabricating membership corroboration from free to real, it does **not** stop a well-resourced
attacker.

## Combined with the cluster-nesting cross-check

`corroboration::ClaimCorroboration::best_corroborated_value_fully_cross_checked(claim_id,
mesh_tree, membership_registry, min_bridge_corroboration, min_membership_corroboration)` is the
fully-combined view: it drops a report if its `reporter_cluster` isn't attested as a real cluster
name at all (`spec/02`'s check), *and* drops it if the reporting peer isn't attested, via this
file's `MembershipRegistry`, as a genuine member of that cluster. It returns a
`FullyCrossCheckedAgreement { best, reports_dropped_unattested_cluster,
reports_dropped_unattested_membership }` so a caller can tell which check a given report failed.
`GET /oag-mesh/v1/claim-report/{claim_id}/best-fully-cross-checked?min_bridge_corroboration=N&min_membership_corroboration=M`
exposes this over the wire, same node-local-only scope as the other read endpoints.

## What this explicitly is not (yet)

- **Does not verify the attester's own standing.** Nothing here checks that an attester vouching
  for a subject's membership in `cluster` is itself a genuine, established member of `cluster` --
  an attester is just another self-asserting `PeerIdentity`, exactly like a `BridgeDeclaration`'s
  signer. Proof-of-work taxes the cost of minting fresh attesting identities; it does not verify
  they're genuinely established members either. A chain of attestations is turtles all the way
  down without some external root of trust (binding a cluster identity to an operator's existing
  PKI, DNS, or other out-of-band credential) -- out of scope for this protocol layer. See
  `spec/01-overview.md`'s "proof-of-work bounds cost, not identity" note, which applies here one
  level deeper than it did for `spec/02`/`spec/05`.
- **Transport is push-and-pull, same as every other mechanism here.**
  `broadcast_membership_attestation` reaches only statically-configured peers that are online at
  that moment; `pull_and_merge`/`sync_with_all_peers` (`spec/10-anti-entropy.md`) close the
  "offline at broadcast time" gap, at the cost of trusting the source peer's own prior
  verification rather than re-checking a signature itself.
- **Persistence is manual and not crash-safe (`spec/08-persistence.md`).**
  `MembershipRegistry::snapshot`/`from_snapshot` cover save/load via
  `transport::MeshState::save_to_dir`/`load_from_dir`, nothing calls them automatically.
- **No weighting by how many subjects an attester vouches for, or how often.** A single attester
  spamming attestations for many different subjects in the same cluster is not flagged or rate
  limited any differently than one attestation -- each `(cluster, subject_peer_id)` pair's
  proof-of-work is independent.

## Tests

`crates/oag-mesh/src/membership.rs` (15 unit tests): sign/verify round trip, self-attestation
rejected both at build time and independently at verify time (hand-constructing one to prove
`verify` enforces it rather than trusting the constructor), tampered-field/mismatched-key/stale-
timestamp rejection, corroboration counting distinct attesters rather than repeated attestations,
`is_attested_member`'s existence/minimum-corroboration check, an invalid attestation never
recorded, an attestation with no proof-of-work rejected, an attester re-attesting the same fact
requiring no proof-of-work, required difficulty escalating with each additional distinct attester
on one subject (and a stale proof no longer being enough), a proof-of-work bound to its own
attestation and unable to be reused, a snapshot round-tripping through `from_snapshot`, and
`merge_snapshot` unioning attester sets idempotently (see `spec/10-anti-entropy.md`).
`crates/oag-mesh/src/corroboration.rs` adds 3 more for the combined view: the full cross-check
drops a report from a peer with no membership attestation while the half-cross-check (cluster name
only) still lets it through; the full cross-check still drops reports claiming an unattested
cluster name outright; the full cross-check against an unknown claim returns `None`.
`crates/oag-mesh/src/transport.rs` adds 5 more: a pushed attestation (with valid proof-of-work) is
recorded; a tampered one is rejected over the wire; `broadcast_membership_attestation` reaches
every configured peer; `.../best-fully-cross-checked` drops a report from an unattested-membership
peer while still counting one with both checks satisfied; `.../best-fully-cross-checked` against
an unknown claim returns a `null` result.
