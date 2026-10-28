# RFC: Owner-Controlled Small-Data Contributions for Cancer Research

**Status: proposed design, not implemented.** No collector, health-data vault, consent
registry, scheduled key release, or research pipeline exists in this repository as a result
of this RFC. This is a separate, opt-in research-data mechanism, not an extension to the
identity-stripped `AnonymousEvent` payload in [the life-saving event RFC](03-anonymous-event-rfc.md).

## Founding request

The creator's request, recorded verbatim:

> we now need to implement data collection techniques that gather small data that seems like it does not matter to gather information about environmental and lifestyle and genetic factors for cancer - public data dediated and vault encrypted for release at a certian date and time depending on the creators release - the creators are the people the data is about - add something somewhere about ownership

## Purpose

Enable people to voluntarily contribute small observations that may seem insignificant on
their own but, over time and with appropriate research methods, may help researchers study
associations between environmental exposures, lifestyle, genetic factors, and cancer.

Small does not mean harmless or scientifically meaningful by default. Combining ordinary
observations can reveal identity, location, health, and family relationships. This proposal
is not permission to silently collect everything, monitor populations, diagnose cancer, or
infer that a correlation establishes causation.

## Ownership: the person the data is about is its creator

For personal observations in this proposal, **the person the data is about is the creator
and owner**, even when a sensor, app, laboratory, clinician, or researcher records the
measurement. Recording, processing, hosting, paying for, or relaying the data does not by
itself transfer ownership. A technical signing key identifies an authorization credential,
not proof of biological identity or ownership.

The owner controls:

- Whether collection starts and which categories are collected; collection is off by default.
- What is retained locally, contributed, corrected, or excluded.
- Whether a contribution is dedicated to public research now, kept private in an encrypted
  vault, or scheduled for a later release.
- The release date and time, audience, purpose, granularity, and scope of an authorization.
- Cancelling or postponing an unreleased contribution and stopping future collection.
- Exporting their data and delegating narrowly defined authority without transferring ownership.

Consent must be explicit, understandable, category-specific, and versioned. Consent to
emergency reporting is not consent to research collection or genetic analysis. No rights
are assigned to a custodian by possession alone. This is a protocol governance principle,
not a claim that software overrides applicable law or resolves all legal ownership questions.

Genetic data also concerns relatives. One person's authorization does not authorize collecting
another person's records, identifying relatives, or publishing another person's genetic
information. Jointly concerning data, minors, delegated authority, and conflicting rights
need a reviewed policy before deployment; they are not silently treated as single-owner cases.

## Proposed collection techniques

Use a dedicated, owner-controlled research collector with a visible preview before contribution.
All techniques below are proposed, not existing capabilities:

| Technique | Small observations | Collection boundary |
|---|---|---|
| Short optional diaries | Sleep duration, activity, diet categories, tobacco/alcohol exposure, occupational exposure categories | Structured, skippable prompts; do not require narratives or third-party names |
| Opt-in sensor summaries | Daily activity totals or calibrated local air-quality measurements | Compute summaries locally; do not upload raw movement traces or continuous audio/video |
| Owner-approved public environmental data linkage | Air pollution, water-quality reports, UV, or environmental exposure estimates for a chosen coarse region/time interval | Record source and uncertainty; no automatic location tracking or disclosure of home/work addresses |
| Participant-directed historical imports | Selected exposure history, relevant clinical outcomes, or existing measurements | Preview fields and time range; distinguish self-report from a clinically documented result |
| Explicit genetic contribution | Selected existing test results or variants voluntarily supplied by the person | Separate consent and higher-sensitivity review; no default raw-genome upload or inferred relatives |

For each observation, retain an appropriately protected, versioned record of category, units,
source/method, measurement interval, precision, uncertainty, missingness, and consent/policy
version. Preserve enough provenance for researchers to distinguish a measured exposure from
an estimate. Collect only fields justified by a stated research purpose; do not invent clinical
thresholds or a universally valid sampling cadence here.

Longitudinal linkage is owner-controlled and private by default. Stable public identifiers
must not make a person's observations trivially linkable across studies. A pseudonym or hash
alone is not anonymization. Exact dates, rare exposures, combinations of traits, and genetic
variants can re-identify someone even without a name.

## Three owner-selected contribution modes

1. **Public research dedication now.** The owner explicitly chooses a reviewed subset or
   aggregate for immediate public research release. Explain audience, license/usage terms,
   and irreversibility before authorization. Public release is not the default.
2. **Private encrypted vault.** Keep contributions encrypted with no scheduled public release.
   Any restricted research access requires a separate, scoped owner authorization.
3. **Scheduled release from the vault.** The owner authorizes a specific contribution/version
   to a specified audience (including public, only if explicitly selected), no earlier than a
   chosen date and time. Keeping a vault is not itself consent to release its contents.

Use a per-contribution policy, not an account-wide switch that accidentally publishes an
entire history. Public dedication does not transfer ownership to a platform, custodian, or
researcher. It does allow copying that the protocol cannot subsequently undo.

## Vault and scheduled-release requirements

- Encrypt locally before distributing a contribution. Use established authenticated encryption
  and independently generated data keys; do not design new cryptography in this RFC.
- Keep keys separate from ciphertext. Redundant custodians should not receive decryption keys
  merely because they store data. Health/genetic values and identifying consent metadata must
  not appear in public OAG assertions, gossip, URLs, or operational logs.
- Bind authorization to an exact encrypted object/version and release policy. Include a UTC
  `not_before` instant, the owner's original timezone choice, audience, permitted scope, and
  policy version. Resolve ambiguous daylight-saving times explicitly in the interface.
- Model at least `private`, `scheduled`, `cancelled`, and `released` states. Policy updates
  must supersede old schedules so a cancelled job cannot later publish an obsolete grant.
- Before release, recheck current owner authorization, object version, cancellation status,
  intended audience, and a trustworthy time source. Fail closed on ambiguity. Do not use an
  untrusted relay's clock as authority to release a key early.
- Cancellation or postponement before key disclosure must prevent future authorized release.
  Release retries must be idempotent and must never broaden the audience or data subset.
- Record a protected release receipt identifying what was actually disclosed and under which
  policy. Preserve a clear distinction between authorization and successful delivery.

**A timestamp is not a cryptographic lock.** A custodian or service holding a usable key can
leak it early. A concrete key-holder/trust model (owner device, delegated release service,
threshold custodians, or another reviewed design) must be chosen and threat-modeled before
implementation. No trustless timed-release guarantee is claimed here. If the owner is offline
at release time, liveness depends on that choice; the system must not quietly grant itself a
permanent key to make scheduling convenient.

**Public release cannot reliably be recalled.** After plaintext or a usable key becomes public,
withdrawal can stop future authorized distribution, not erase copies or make recipients forget.
Even restricted recipients can retain plaintext. Do not describe agreement expiry, revocation,
or key rotation as guaranteed removal of already disclosed data.

## Research and privacy requirements

- Prefer reviewed aggregates or restricted research access over publishing individual-level
  health/genetic histories. Raw genetic publication is not a default collection or release path.
- Evaluate linkage and re-identification risk across contributions, not just one small record.
  Minimum cohort sizes and suppression rules require study-specific review; none is asserted
  here to guarantee anonymity. Differential privacy, if used, needs an explicit budget and
  utility analysis, not merely a label.
- Explain that volunteering data does not promise a diagnosis, treatment, or scientific benefit.
  Study design must address confounding, selection bias, measurement error, missingness, and
  validation. Corroboration of a hash proves neither clinical accuracy nor cancer causation.
- Require appropriate research ethics, security, and jurisdictional review before real collection.
  Researchers receive only the scope the owner authorized; secondary uses need their own basis.

## Relationship to the existing projects

- `oag-mesh` may eventually transport encrypted objects and corroborate provenance/availability
  claims across clusters. Its current push-only HTTP transport is not already a health-data
  vault, durable replication service, anonymous research collector, or scheduled-release system.
- `open-agent-graph` may anchor carefully minimized ownership/authorization assertions. Its
  signed append-only records are not a place to publish sensitive personal payloads or
  identifying metadata that later needs deletion. Exact integration remains undesigned.
- [Data Roads](https://github.com/webdawg/data-roads) supplies the related owner/custodian and
  access-agreement design vocabulary. Its generator-as-owner rule is specialized here to mean
  the **person the personal data concerns**, not the measuring instrument or its operator.
  Public dedication is distinct from its renewable restricted-access model; neither model can
  retract plaintext already copied. This RFC does not silently change the Data Roads RFC.
- The emergency-reporting RFC stays closed-schema and identity-stripped. Do not add diaries,
  genomes, patient identifiers, or longitudinal records to `AnonymousEvent` to implement this.

## Implementation gates and acceptance criteria

Before collecting real data, settle the record/consent schema, owner authorization and recovery,
key custody and release trust model, retention/deletion policy, and research review process.
Implementation should start with synthetic records and a local-only prototype, not live scraping
or automatic publication of people's health data.

Required tests include: no collection without opt-in; category-specific consent; no plaintext
leaks to public logs/graph/transport; explicit public-release confirmation; no early release;
cancel/postpone races and stale jobs; object/policy-version mismatch; unauthorized audience;
clock uncertainty and timezone boundaries; retries/restarts; and owner/key unavailability.
Document which guarantees depend on honest services and which are enforced cryptographically.

Open decisions include the collector's repository boundary, permitted study categories, concrete
cryptographic libraries, release service availability, joint/family rights, succession if an
owner dies, and how corrections/withdrawals propagate without publishing sensitive metadata.
No release-on-death or automatic inheritance policy is implied by a chosen date and time.
