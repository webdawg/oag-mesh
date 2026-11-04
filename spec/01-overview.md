# Overview

**Status: all three mechanisms below are implemented (`spec/02`, `spec/03`, `spec/05`), plus a
fourth, `spec/09-cluster-membership-attestation.md`, that closes the second half of a gap
`spec/02`/`spec/05` both left open. A real HTTP transport covers all four
(`spec/04-transport.md`), with both push (`broadcast_*`) and pull-based anti-entropy
(`pull_and_merge`/`sync_with_all_peers`, `spec/10-anti-entropy.md`) now reaching a peer that was
offline for a specific broadcast, and manual, non-crash-safe persistence covers all four stores
(`spec/08-persistence.md`). All four message types now require escalating proof-of-work before
recording a submission (`spec/02`'s, `spec/03`'s, `spec/05`'s, and `spec/09`'s own
"Anti-sybil"/"Anti-spam" sections). `spec/05`'s claim reports can be cross-checked against real
cluster nesting alone (the cluster *name* being real,
`best_corroborated_value_cross_checked`) or against both that **and** `spec/09`'s membership
attestations (the *reporter's own standing* in that cluster,
`best_corroborated_value_fully_cross_checked`) -- see `spec/02`'s, `spec/05`'s, and `spec/09`'s
own sections for exactly what each layer does and does not cover; even fully cross-checked, an
attester's own standing is itself unverified, one level deeper still. Full dispatch-to-a-responder
for anonymous events is still not designed, though one narrow slice of it now is --
`spec/11-responder-search.md`'s filterable, anonymous search over a node's own log -- explicitly
not dispatch, notification, or duplicate-response prevention, see that file for where the line is
drawn. Verifying that distinct `PeerIdentity`s are genuinely different organizations (not just
different keys), and automatic/crash-safe persistence, remain unaddressed. Pull-based
anti-entropy's own trade-off -- it trusts a peer's prior verification rather than re-deriving it,
a weaker guarantee than push -- is stated in `spec/10`'s own section on exactly that.**

## What this layer is

Four related mechanisms, one level above a single `oag` peer or peer cluster:

1. **Clusters within clusters, implemented — see `spec/02-cluster-nesting.md`.** The base
   project's peer clustering (`spec/26-peer-clustering.md` there) gives a peer exactly one flat
   cluster name, by design, in its first version. Rather than lifting that constraint inside the
   base project's own `oag-sync` (changing working code to fit a new, separate layer's needs),
   nesting is implemented entirely in *this* repository instead: a peer signs a
   `BridgeDeclaration` placing a base-layer cluster name — or another mesh-group, recursively —
   into a named mesh-group, under this crate's own domain-separated message format. The base
   project is completely untouched; a `[cluster].name` keeps meaning exactly what it already
   means there. Two base clusters nested under the same mesh-group stay distinct federation
   domains; nesting is a fact tracked here, not a change to how the base project's own
   `FederationPolicy`/trust configuration works for either cluster's members. A declaration now
   also carries escalating proof-of-work (`spec/02`'s "Anti-sybil resistance") taxing the cost of
   becoming a *new* distinct peer corroborating an edge — this matters beyond mechanism (1) on
   its own, since mechanism (2)'s cross-check (below) leans on this mechanism's data to decide
   whether a claimed cluster name is real.
2. **Federated corroboration, implemented — see `spec/05-federated-corroboration.md`.** Multiple
   independently-operated nodes (potentially across different clusters/organizations) receive or
   fetch the *same* claim, content, or gateway answer, each through its own path, and sign a
   `ClaimReport` of what they got. Comparing those — do the content hashes agree? — is a
   verification signal: agreement across independent, *differently-clustered* paths is real
   corroboration; a self-asserted `reporter_cluster` is what makes "differently-clustered"
   checkable at all (weighted by distinct cluster, not just distinct peer — see `spec/05`'s own
   "why weight by cluster" section for why that distinction matters). A submission now also
   carries escalating proof-of-work (`spec/05`'s "Anti-sybil resistance") taxing the cost of
   claiming a *new* distinct cluster on a claim — raising the cost of fabricating cluster
   diversity from free to real, without requiring that cost for repeat reports from a cluster
   already corroborating the claim. `reporter_cluster` can also be cross-checked against
   mechanism (1)'s real `bridge::MeshTree` data (`best_corroborated_value_cross_checked`) —
   confirming the claimed cluster *name* was really attested by a `BridgeDeclaration` somewhere.
   Combined with mechanism (4) below (`best_corroborated_value_fully_cross_checked`), it also
   confirms the reporting peer actually belongs to that cluster, not just that the name is real
   (see `spec/05`'s own section on exactly where the remaining line is drawn). This is the
   witness/audit mechanism named in the base project's `spec/22-future-work.md` and its
   `future_flood_propagation_and_anonymity.md`/`future_service_announcements_and_audit.md` memory
   entries, and the mechanism `spec/32-verified-internet-gateway.md`'s own quorum fan-out already
   implements for one peer's gateway queries — this layer is the same idea generalized across
   organizational/cluster boundaries instead of one peer's own configured query_peers.
3. **Anonymous event reporting for life-saving actions, schema implemented — see
   `spec/03-anonymous-event-rfc.md`.** A deliberately different, identity-*stripped* mechanism
   from (1), (2), and (4), which are all signed-identity-based: an `AnonymousEvent` ("SAW THIS
   EVENT" — a sighting, a hazard, a medical emergency, a resource need) carries no persistent
   signature, no precise location or time, and no free-text field that could smuggle an
   identifying description of a person. Corroboration here means independent reports converging
   on the same `corroboration_nonce`, not counting distinct signing peers. A node's own log can
   now be searched/filtered by kind, minimum severity, location prefix, or recency
   (`spec/11-responder-search.md`) -- the one narrow slice of "reaching a responder" this crate
   answers, explicitly not dispatch, notification, or anything that identifies a responder.
4. **Cluster membership attestation, implemented — see
   `spec/09-cluster-membership-attestation.md`.** Closes the half of mechanism (2)'s cross-check
   gap that mechanism (1) alone can't: a `BridgeDeclaration` only ever says a cluster *name* is
   nested somewhere, never which peers belong to it. A `MembershipAttestation`, signed by some
   *other* peer ("I attest peer P is a genuine member of cluster C"), corroborated by distinct
   attester count, with its own escalating proof-of-work (`spec/09`'s "Anti-sybil resistance")
   taxing the cost of becoming a new distinct attester for one membership claim. Does not verify
   the attester's own standing in C either — stated plainly in `spec/09`, the same
   "proof-of-work bounds cost, not identity" gap one level deeper.

## What this layer explicitly is not

- **Not a tool for monitoring individuals, communications, or populations.** The data being
  corroborated is a claim or content a peer already holds or fetched — the same evidence-backed,
  non-authoritative model the base project's whole graph is built on — not a feed of information
  *about* a person or group. A request to build this layer as mass-surveillance infrastructure
  ("global cluster surveillance," multiple organizations monitoring and redacting shared data
  streams) was made and explicitly declined before this repository existed — see the base
  repository's `USER_INPUT_RECORD.md` Entry 25 for the verbatim exchange. This boundary is a
  condition of this repository's existence, not a footnote.
- **Not a trust merger.** Cluster A and cluster B stay separate federation domains even after a
  bridge peer connects them. No change here makes a non-bridge member of A automatically trust a
  non-bridge member of B.
- **Not yet a video streaming protocol.** Raised in the same conversation as this layer, but
  independent of it — if built, it's a new `GatewayService` variant in the base project's
  `spec/32-verified-internet-gateway.md`, not part of this repository.

## Proposed research-data extension (not implemented)

[Owner-controlled small-data contributions for cancer research](06-owner-controlled-cancer-research-data-rfc.md)
is a separate draft for voluntary environmental, lifestyle, and genetic observations, with
subject-as-creator ownership and explicit public/private/scheduled-release choices. It does
not widen `AnonymousEvent`, authorize population monitoring, or represent an implemented
collection, vault, or release capability. See that RFC for current requirements and open decisions.

## Open design questions (not yet resolved)

- Whether corroboration findings (agreement/disagreement across paths) get written back into the
  base project's evidence/corroboration model, or live entirely in this layer's own storage.
- **"Independent enough" is answered for mechanism (2), not for (3).** `spec/05`'s
  distinct-cluster weighting is the concrete answer for `ClaimReport` corroboration (two reports
  from the same self-asserted cluster count as one). The anonymous-event mechanism (3) has no
  identity at all to attach a cluster claim to, so the same fix doesn't transfer — it still just
  counts raw report volume under a nonce, mitigated only by proof-of-work's escalating cost, a
  different (and weaker) kind of "independent enough."
- A real HTTP transport exists now for all four mechanisms (`spec/04-transport.md`), with both
  push and pull-based anti-entropy (`spec/10-anti-entropy.md`), and explicit that it does not
  give `AnonymousEvent` submissions any network-level anonymity on top of their already-anonymous
  payload. All four message types now require escalating proof-of-work before being recorded --
  `BridgeDeclaration` (`spec/02`'s "Anti-sybil resistance"), `AnonymousEvent` (`spec/03`'s
  "Anti-spam and anti-replay"), `ClaimReport` (`spec/05`'s "Anti-sybil resistance"), and
  `MembershipAttestation` (`spec/09`'s "Anti-sybil resistance") -- real mitigations, not full
  solutions, and each says so explicitly: none stops a well-resourced attacker, each only taxes
  the specific thing its own mechanism's corroboration count depends on (a new distinct peer on a
  mesh edge, raw report volume under a nonce, a new distinct cluster on a claim, or a new distinct
  attester on a membership claim, respectively).
- **Proof-of-work bounds cost, not identity.** Across all four mechanisms, a well-resourced
  single operator can still pay the escalating cost to mint several real, distinct
  `PeerIdentity`s and have each independently corroborate the same fact -- proof-of-work makes
  that cost something instead of nothing, it does not verify the identities behind it are
  genuinely different organizations. This is the same "independent enough" gap as the bullet
  above, now stated once for all four mechanisms rather than per-mechanism: no amount of
  proof-of-work alone, as designed here, resolves it. `spec/09-cluster-membership-attestation.md`
  closes the specific gap this bullet used to flag -- a fabricated claim of *membership* in a
  real, already-attested cluster is no longer free to make pass unnoticed, since
  `best_corroborated_value_fully_cross_checked` requires a real `MembershipAttestation` too --
  but one level deeper, the same gap reappears: nothing verifies an *attester's* own standing in
  the cluster it's vouching for, either. Minting fresh `PeerIdentity`s that each pay escalating
  proof-of-work to attest a subject's membership in a cluster none of them actually belong to
  still works, just no longer for free, and with one more layer of indirection to climb through.
  See `spec/02`'s, `spec/03`'s, `spec/04`'s, `spec/05`'s, and `spec/09`'s own "open questions"
  sections for what else is still unresolved.
- **Pull-based anti-entropy trusts a peer's own prior verification, it does not re-derive it.**
  `spec/10-anti-entropy.md`'s `pull_and_merge` closes the "offline during a broadcast" gap by
  merging a peer's whole snapshot, but a snapshot has already collapsed past the original signed
  message -- there's no signature left to re-check on a pull, unlike every push handler's own
  independent re-verification. This is a new, different trust boundary from the "mint fresh
  `PeerIdentity`s" gap above, not the same one restated: it's about trusting the specific peers
  already on `MeshState.peers`'s list to report their own state honestly, not about how many
  identities an attacker can mint.
