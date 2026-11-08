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
- **Persistence is manual and not crash-safe.** Assumption: caller decides when to save; a crash
  mid-write can lose or corrupt a file. Status: open.

## Cross-store consistency

- **No atomic multi-store operations.** Assumption: best-effort per store. A failed store pull
  leaves its last-known heads unrecorded so the next pull retries it, but there is no
  transaction across the five stores. Status: open.
