# Open Questions

Design/scope questions that came up during background work, consolidated from the `spec/` files.
Each one has the default assumption being proceeded with, so work keeps moving instead of
blocking. Override any of these any time — ask "are there open questions?" or edit this file
directly.

Format: question, assumption being run with, status.

## Reaching a responder (spec/03, spec/11, spec/12)

- **How does a report reach someone who can act on it, without identifying the reporter or the
  responder?** Assumption: deferred. `spec/11`'s filterable search and `spec/12`'s advisory
  acknowledgment are the only built slices; there is no dispatch, notification, responder
  identity, or subscription. Status: open.
- **An `AllClear` adds an entry under a nonce rather than removing the resolved situation from
  view.** Assumption: the retention primitive (`prune_before`/`prune_expired`, and the
  `POST .../prune` endpoint) is the operator's tool for bounding the log; what an `AllClear`
  should semantically do is still undecided. Status: open.
- **Nothing pushes an acknowledgment to anyone.** Assumption: polling only -- a responder must
  already be querying `GET .../responder-acknowledgment/{nonce}` or re-running a search. Status:
  open.

## Identity and trust (spec/01, spec/02, spec/05, spec/09)

- **Are distinct `PeerIdentity`s genuinely different organizations?** Assumption: unsolvable at
  the protocol level. Proof-of-work taxes cost, not identity; an external root of trust (PKI,
  DNS, or another out-of-band credential) is out of scope. Status: open.
- **An attester's own standing in the cluster it vouches for is unverified.** Assumption: out of
  scope -- the same "turtles all the way down" gap, one level deeper. `spec/09` closes the
  subject's membership, not the attester's. Status: open.
- **"Independent enough" for anonymous events is answered by proof-of-work, not by cluster
  weighting.** Assumption: `spec/05`'s distinct-cluster weighting does not transfer to the
  identity-stripped event log; raw report volume under a nonce, taxed by escalating proof-of-work,
  is the only mitigation. Status: open.

## Transport and anonymity (spec/03, spec/04)

- **A plain HTTP POST reveals the reporter's source IP.** Assumption: deferred. The payload is
  identity-stripped; the transport is not. A real anonymizing submission path (onion-style
  relaying, an intermediary that does not log source-to-content correlation) is not built. Status:
  open.
- **The `GET` endpoints have no auth.** Assumption: operator-configured network trust -- the same
  posture as the base project's `GET /metrics`. A deployment exposing them more widely needs its
  own gating. Status: open.
- **Responder acknowledgments are rate-limited by identity, but not authenticated.** Assumption:
  the per-identity fixed-window limit (`spec/12`) is a cost bound, not a reputation system or an
  allowlist; the defaults (60 per 60s) are a starting point. Status: open (revisit if a real
  deployment needs reputation).

## Resource bounds and proof-of-work (spec/03, spec/10, spec/13)

- **Proof-of-work difficulty is untuned.** Assumption: `BASE_DIFFICULTY_BITS`/
  `DIFFICULTY_STEP_BITS` are reasonable defaults, not derived from a real deployment's hardware
  or traffic. A real deployment should retune. Status: open.
- **Proof-of-work does not stop a well-resourced attacker.** Assumption: stated plainly in every
  proof-of-work-bearing mechanism -- it raises cost from free to real, it does not bound volume
  outright. A botnet solves it as fast as anyone. Status: open (accepted trade-off).
- **Distributed route search does not deduplicate against results already in flight.** Assumption:
  the "shortest path among those found" guarantee is kept, and the extra network work that
  entails is accepted. A short-circuit-on-first-result variant would trade that guarantee for
  less work. Status: open.
- **Pull-based anti-entropy does not re-verify signatures.** Assumption: trusting the configured
  peer list, stated plainly in `spec/10`. A pulled snapshot has already collapsed past the
  signed messages; there is nothing left to re-check. Status: open (accepted trade-off).
- **Persistence is manual and per-file crash-safe; cross-file consistency is now enforced by a
  commit marker.** Assumption: caller decides when to save -- that part is unchanged. A crash
  mid-write can no longer *corrupt* a file (temp + rename, per `spec/08`), and it can no longer
  leave a silently-torn *set*: `save_to_dir` writes the seven files and then a `commit.json`
  recording each file's BLAKE3, and `load_from_dir` refuses the set with `TornSet` if any recorded
  file is missing or differs. A directory with no marker still loads as before, so upgrading
  never strands existing state. What remains: a power loss can still lose the rename itself
  (there is no fsync), and a caller that saves rarely can still lose up to a whole save's worth of
  in-memory state. Status: resolved for torn-set detection; open for fsync/durability.

## Link quality and adaptive ordering (spec/13)

- **Does observed deliverability actually improve routing?** Assumption: yes for the one thing it
  can improve -- which peer a scarce fan-out budget is spent on. `link_quality` records whether
  each interaction delivered and route search asks its peers best-first. It is *not* a routing
  table: it does not pick the next hop, it does not change what "shortest path" means, and it does
  not discover peers. `a_failed_fan_out_is_recorded_and_the_next_search_spends_its_budget_better`
  measures the effect on a real loopback network (one dead peer, budget of one: the first search
  fails, the second succeeds after a single observation). Status: implemented and measured on that
  one axis; open on the axes it deliberately does not touch.
- **A peer that is down is asked last, never not asked.** Assumption: "degrade, don't drop" applies
  to connectivity, not only to federation. The ordering function is a permutation of the input --
  every configured address appears exactly once -- and that is asserted as a property test rather
  than left as a comment. Status: resolved.
- **The score is a liveness signal, not a trust signal.** Assumption: a peer that answers with
  garbage scores exactly as well as one that answers correctly. Honesty is `spec/05`'s
  corroboration layer's job. Nothing here feeds `trust_score` or any federation decision.
  Status: resolved (deliberate scope).
- **Quality is forgotten on restart.** Assumption: re-learning it costs a little wasted fan-out,
  which is the same posture as the crate's other limiter state. Persisting it would add an eighth
  store and change the commit-marker set for a value that is by nature ephemeral. Status: resolved
  (accepted trade-off).

## Cross-store consistency

- **No atomic multi-store *writes*.** Assumption: the commit marker (`spec/08`) makes a saved set
  atomic *to a reader* -- either the whole set is on disk and verified, or the load is refused --
  but there is still no multi-store transaction on the write side, and no atomicity across a pull
  that updates several stores. A failed store pull leaves its last-known heads unrecorded so the
  next pull retries it. Status: open (the marker closed the read-side gap; the write-side pull gap
  is unchanged and is the smaller of the two).
