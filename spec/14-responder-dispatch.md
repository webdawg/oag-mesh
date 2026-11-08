# Responder Dispatch

**Source**: `crates/oag-mesh/src/dispatch.rs`, `crates/oag-mesh/src/transport.rs`
(`/oag-mesh/v1/responder-subscriptions`, `/oag-mesh/v1/responder-inbox/{subscription_id}`).

The narrowest honest slice of `spec/03-anonymous-event-rfc.md`'s "Reaching a responder" open
question: a responder can receive the events it cares about without the node learning who it is.

## The mechanism

A responder generates a random `subscription_id` and registers a filter:

    POST /oag-mesh/v1/responder-subscriptions
    { "subscription_id": "<random>", "kind": "MedicalEmergency", "min_severity": "High" }

The node stores `subscription_id -> filter`. The id is chosen by the responder, so the node never
learns which `PeerIdentity` stands behind it -- only that a subscription exists.

When an anonymous event is recorded, the node appends it to every subscription whose filter
matches:

    GET /oag-mesh/v1/responder-inbox/{subscription_id}
    -> { "events": [ ... ] }

The inbox is drained on read. Nothing is pushed: the responder has to poll. A responder can
replace its filter by re-registering, or remove it with
`DELETE /oag-mesh/v1/responder-subscriptions/{subscription_id}`.

## What this explicitly is not

- **Not a push notification.** Nothing leaves the node until the responder polls. A responder
  that never polls sees nothing, and a responder that polls only sees what has arrived since its
  last poll.
- **The node learns the responder's network address.** The responder has to reach the node to
  register and to poll, so the node sees its IP -- just not its `PeerIdentity`. This is a weaker
  anonymity guarantee than the reporter's: a responder is choosing to act, and the mechanism
  deliberately does not hide its network location from the node it uses.
- **Persisted, but not an acked queue.** `spec/08`'s `save_to_dir`/`load_from_dir` cover both
  the subscription registry (`responder_subscriptions.json`) and the inbox
  (`responder_inbox.json`), so a restart no longer loses them. The inbox is still drained on
  read, not acked -- a responder that never polls accumulates events until it does, and a crash
  between a save and a drain is the only loss window. Events are never lost from the log, only
  from the inbox.
- **Not a guarantee that a responder is reachable at all.** The mechanism only guarantees that,
  if a responder polls, it will see the events it asked for.
- **Not a lock or an acknowledgment.** This is delivery, not a claim-to-handling -- that remains
  `spec/12`'s separate, advisory mechanism.
- **Node-local, no auth** -- same posture as every other endpoint here. Anyone who can reach the
  listen address can register a subscription and drain its inbox; the inbox is only as private as
  the subscription id, which is a bearer token. A real deployment exposing this more widely needs
  its own gating.

## Tests

`crates/oag-mesh/src/dispatch.rs` adds 3 unit tests: a matching event is queued for a subscription
and a non-matching one is not; the inbox drains on read; a subscription is blinded and
replaceable. `crates/oag-mesh/src/transport.rs` adds 3 more over real HTTP: a subscription
receives only matching events and drains on poll; unregistering stops delivery and a second
unregister is `404`; and `save_to_dir`/`load_from_dir` round-trips both the subscription registry
and the inbox.
