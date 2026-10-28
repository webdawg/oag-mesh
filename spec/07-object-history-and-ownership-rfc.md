# RFC: Global Object Identity, History, and Ownership-Gated Data Exchange

**Status: proposed, not implemented.** This is a serious, general-purpose protocol direction
for globally addressable object histories, not just a product inventory feature. Wire formats,
proof profiles, storage interfaces, and dispute governance remain to be designed.

## Founding request

> add more data that surrounds objects that you get access to when you own the unique object - houses, cars, etc - get unique ids where you need to prove ownership to get the informaiton, and also provide others the information, and maintain partner ships in data - i have to prove ownership - this is part of the back and forth - data storage options need to be constructed, possibly stored in deed etc of house, or whatever - i dont care if we are creating unique ids to marbles or rocks - IE x rock history - this is a serious protocal for global object tracking - add this concept to the event and storage RFC

## Scope: any unique object, not only high-value property

An object may be a house, parcel, car, appliance, component, marble, rock, specimen, or another
physical thing. No market-value threshold is required. An object history can include origin,
construction/materials, manufacturing, maintenance, repair, inspection, condition, environmental
measurements, provenance, ownership claims, and authorized contributions from data partners.

Examples: a house's water tests, building materials, repairs, and inspection history; a car's
maintenance and component replacements; or "rock X" and its documented origin, observations,
transfers, and chain of custody. Observations remain attributed claims with evidence, not truth
merely because they were signed or associated with an ID.

"Global object tracking" means persistent object identity and authorized history exchange
across systems and owners. It does not require continuous geolocation, reveal every owner,
or authorize tracking people's movements. Location histories, occupancy, routes, and household
health observations need their own permissions; owning a house or car does not grant rights
over the people using it.

## Object identity and physical binding

- Give each object a stable, globally collision-resistant ID, using a reviewed decentralized
  identifier/namespace scheme rather than requiring one worldwide issuer. Exact encoding is open.
- Separate the ID from owner identity, storage location, encryption keys, and existing legal
  identifiers. Ownership and hosting can change without changing the object's historical ID.
- Allow evidence-backed aliases for VINs, parcel/title references, serial numbers, specimen
  catalog numbers, and legacy IDs. Do not expose a sensitive alias publicly by default.
- Establish the link to the physical object through class-appropriate evidence: registration
  or deed records, manufacturer attestations, documented physical characteristics, provenance,
  or inspection. A QR/NFC tag is a locator, not ownership proof; a cloned tag remains possible.
- Handle duplicate registrations, tag replacement/loss, disputed aliases, object destruction,
  and components/splits/merges through explicit events and relationships. Do not silently merge
  histories or treat a newly minted ID as proof that the thing is newly owned.

A person can register an observation about a rock without claiming legally verified ownership
of it. Identity, possession, custody, authorship, and ownership are distinct assertions.

## Ownership proof is part of the back-and-forth

Finding an ID must not unlock its restricted data. A proposed access exchange is:

1. A requester identifies the object and requested records, purpose, duration, and audience.
2. A verifier issues a fresh challenge bound to that request and receiving service.
3. The requester demonstrates control of an authorization key **and** supplies class-appropriate,
   current evidence of ownership or a delegation from an authorized rights holder. Key control
   alone proves neither legal title nor authority over every associated record.
4. The verifier checks evidence issuer/trust policy, scope, validity, freshness, transfer epoch,
   revocation, and disputes; joint ownership may require multiple approvals. Replayed evidence
   or an old owner's credential must not satisfy a current-ownership requirement.
5. The applicable data rights holder authorizes or denies the requested subset. Successful
   verification may yield a short-lived, audience-bound capability or encrypted key grant,
   never an unrestricted permanent master key. Receipt and access decisions are recorded privately.
6. The recipient may return an inspection, repair result, correction, or other agreed contribution;
   the producer's signature/provenance and the object's association are verified independently.
   The owner can share authorized subsets with further parties under separate grants.

Evidence profiles differ: a deed/registry attestation may apply to a house, a title/registration
to a vehicle, and provenance plus corroborated transfer statements to an unregistered collectible.
Cryptography cannot manufacture legal title to an arbitrary rock. State the assurance level,
issuer, jurisdiction where relevant, and unresolved claims rather than inventing certainty.
Protect deeds and identity evidence; selective disclosure is preferable to publishing documents.

## Object ownership and data rights are not the same thing

The goal is that proving ownership enables access to the object's **owner-accessible records**
and the ability to contribute and authorize onward sharing. Whether a particular record is
owner-accessible must itself be specified in its rights policy, not inferred from the object's ID.

A provider may author a repair report; a resident remains the creator/owner of personal health
observations about themselves; a custodian merely hosts ciphertext. Buying the object does not
silently transfer every provider's rights, former occupants' private records, or another person's
genetic data. Separate object title, data authorship/ownership, access entitlement, and delegation.

On sale, transfer only the object-linked records and grants authorized to follow the object.
Retain appropriate service history while excluding prior owners' personal identifiers and unrelated
data. Advance an ownership epoch, revoke old grants, and rewrap/rotate future-access keys where
appropriate. Previously disclosed plaintext cannot be recalled by rotation or ownership transfer.
Disputed transfers must not be resolved by "last signature wins" or simple peer vote.

## Data partnerships: a continuing exchange

Owners, inspectors, mechanics, laboratories, manufacturers, researchers, and custodians can
maintain renewable, object-scoped relationships. A partnership agreement should specify:

- Parties, object IDs, eligible records, each party's authority, and contribution obligations.
- Read/write permissions, purpose, term/renewal, onward-sharing limits, and any consideration.
- Attribution, measurement/provenance requirements, correction procedures, and dispute handling.
- Retention, cancellation, ownership transfer behavior, and treatment of derived datasets.

Partnerships are bidirectional: receiving data is not automatically permission to publish it;
submitting data is not automatically ownership of the object. Expiry ends future authorized
access or writes, not the recipient's physical ability to retain previously received plaintext.

## Proposed object-history events

Use a **separate, versioned event family**, not the closed anonymous emergency schema. Candidate
semantics are registration/binding attestation, observation, service/inspection, ownership claim,
transfer proposal/acceptance/dispute, access request/grant/revocation, partnership establishment/
renewal/end, storage-manifest update, correction, and retirement/split/merge relationships.
These names are design vocabulary, not implemented API variants.

Each event needs an event ID, schema version, object reference, event type, appropriate timestamp
precision, provenance/issuer where required, prior-event references, ownership/policy epoch,
and protected evidence/payload references. Define domain-separated signatures and replay rules
before implementation. A timestamp orders a claim; it is not proof that the claimed event happened.

Choose visibility per field/event. Public discovery must not expose a person's ownership graph,
private addresses, plaintext deeds, health data, or access logs. Even hashes/references can permit
linkage or dictionary attacks. Keep sensitive payloads and identity-bearing metadata encrypted
and off public append-only logs; corrections can supersede a claim but cannot erase public copies.

## Gated auditability: a workflow for global data

The protocol must support auditing claims across global data, including object identity,
ownership, custody, movement, condition, measurements, storage, and research provenance.
"Global" describes interoperable coverage, not a universal permission to read private data.
Auditing is an explicit, gated workflow; being an auditor does not bypass owner authorization,
third-party rights, or the minimum evidence scope needed for a particular question.

A proposed audit workflow is:

1. **Specify the claim and question.** Identify the object/data version, claimed event, interval,
   applicable policy, and what would count as supporting or contradicting evidence.
2. **Authorize a bounded audit.** Verify auditor credentials and delegated authority, purpose,
   conflicts of interest, evidence scope, expiry, and permitted disclosure. Record the request
   and decision privately; the auditor cannot grant itself additional access.
3. **Acquire evidence with provenance.** Request protected records from eligible custodians or
   independent witnesses; verify integrity, issuer, timestamp uncertainty, ownership/custody
   epoch, calibration where relevant, and chain of custody. Disclose only necessary fields or
   reviewed selective proofs. Log evidence versions so the decision can be reproduced.
4. **Cross-check independently.** Compare source records, physical inspections, measurements,
   and mutually acknowledged handoffs. Sources controlled by one party are not independent
   simply because they use different keys, peers, or cluster names. Account for missing data,
   conflicting evidence, compromised devices, and limits of the audit's access.
5. **Issue a scoped finding.** Record the auditor, method, evidence references, uncertainty,
   coverage, limitations, and an explicit outcome: supported/corroborated, disputed,
   inconclusive, or disproved under the stated method. An audit can verify a hash or signature
   while leaving the real-world claim unresolved. No global truth oracle is asserted.
6. **Challenge, correct, and re-audit.** Permit authorized counter-evidence, appeal, independent
   review, and versioned corrections. Preserve the relationship between the original claim
   and findings without publishing private evidence. Define who adjudicates unresolved disputes
   in the applicable policy; popularity or quorum alone must not determine legal/physical truth.

### Movement verification

Movement is a sequence of evidence-backed departure, handoff, receipt, and observation claims,
not automatically a continuous location feed. Where appropriate, a transfer can bind both
parties' acknowledgments to the object, fresh challenge, custody epoch, time interval, and
permitted location precision. Independent inspection or authenticated sensor evidence may
strengthen the record. A signature proves who asserted a movement, not that the physical
object moved; copied tags, colluding parties, sensor spoofing, route gaps, and clock errors
must remain visible limitations. Missing receipts are gaps, not proof that no movement occurred.

Exact routes and locations can identify people or expose valuable objects. Store them encrypted,
release only the scope the audit requires, and prefer coarse or selectively disclosed movement
proofs where sufficient. Ownership of an object is not permission to surveil its occupants,
borrowers, workers, or bystanders. Auditing an environmental or medical dataset similarly does
not grant access to all participants' identities or genomes.

### Audit events and storage obligations

The separate object/data event family should include audit request, authorization/denial,
evidence commitment/submission, finding, challenge, correction, and re-audit semantics. Storage
must retain authorized, integrity-verifiable snapshots long enough for the agreed audit window,
record protected access receipts, and support revocation and expiry of future access. A public
finding may contain only an approved summary; protected evidence and access metadata stay gated.
Append-only evidence references do not justify making personal data permanent or public.

Before implementation, define auditor trust profiles, collusion/conflict handling, proof formats,
retention and reproducibility rules, dispute authorities, and tests for unauthorized evidence
access, fabricated movements, replayed receipts, altered records, and stale or overbroad findings.
The aim is to verify correctness as far as evidence permits, not certify every item of global data
as unquestionably true.

## Storage: attached, documentary, local, and distributed

The companion [Data Roads storage RFC](https://github.com/webdawg/data-roads/blob/main/rfc/0001-data-roads.md)
section "Object-linked records, ownership proof, and documentary storage" defines this proposal's
storage requirements. An object record can be stored locally, with encrypted redundant custodians,
in an offline export, on an attached tag, or through a reference/attestation in a deed, title,
certificate, or physical archive. A document may carry selected durable data or a versioned
manifest locator, but **never a public decryption secret**.

Manifests must support integrity checks, authenticated updates, migration, recovery, and policy
versions without making a mutable URL the sole source of truth. Legal registries need their own
acceptance/integration process; writing an ID into a document does not create legal recognition.
Owner-selected timed releases can apply to eligible object records, subject to the same key-custody
and irreversibility limits as the [owner-controlled research-data RFC](06-owner-controlled-cancer-research-data-rfc.md).

## Before implementation

Settle identifiers and physical binding, per-class ownership assurance, joint/delegated authority,
rights policies, privacy-preserving discovery, event schemas, key custody/recovery, transfer disputes,
and storage/retention responsibilities. Prototype with synthetic houses/cars/rocks and no live titles.

Required tests include copied tags, duplicate IDs, forged or expired proofs, replayed challenges,
old-owner access after transfer, unauthorized partner writes, joint-owner rules, disputed transfer,
split/merge integrity, lost keys, offline documents, migrated storage, revoked grants, and no sensitive
payload or metadata leaking into public logs. Global interoperability and real-world ownership
verification remain goals, not guarantees supplied by today's corroboration or transport code.
