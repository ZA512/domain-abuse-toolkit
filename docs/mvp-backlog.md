# MVP backlog

Priority uses `P0` for release-blocking, `P1` for high-value MVP work, and `P2` for post-MVP capability.

## Epic A — Safe case intake

- `P0` Create a case from an exact URL and brand profile.
- `P0` Preserve exact input and public-suffix-aware normalized fields.
- `P0` Reject prohibited schemes, credentials, ports, and non-public targets.
- `P0` Revalidate every redirect and browser navigation.
- `P1` Batch intake with preview and per-target authorization.

## Epic B — Passive collection

- `P0` Common collector result and error contract.
- `P0` DNS collector with raw and normalized records.
- `P0` RDAP bootstrap discovery and normalized registration summary.
- `P0` HTTP collector with exact path, redirect chain, bounded raw body, digest, and safe headers.
- `P0` TLS collector with certificate bytes, SAN, validity, and SHA-256 fingerprint.
- `P1` IP/ASN and abuse-contact enrichment from approved sources.
- `P1` Provider hints with evidence and confidence.

## Epic C — Evidence

- `P0` Evidence store with path confinement and SHA-256 manifest.
- `P0` Preserve original versus derived classification.
- `P0` ZIP export and offline manifest verification.
- `P0` Isolated desktop screenshot worker.
- `P1` Mobile screenshot and printable PDF derivative.
- `P2` WARC/WACZ export and optional signing/timestamping.

## Epic D — Qualification and workflow

- `P0` Five-question operator validation desk.
- `P0` Explainable criticality proposal and human confirmation.
- `P0` Versioned workflow rules that generate actions and deadlines.
- `P0` Action timeline with owner, proof, channel, and external reference.
- `P1` Scheduled checks and overdue dashboard.
- `P1` Snapshot diff and change-first review.

## Epic E — Drafts and external assistance

- `P0` Versioned bilingual deterministic clause library.
- `P0` Initial, reminder, and escalation draft assembly.
- `P0` Copy subject/body and `mailto:` fallback.
- `P0` Form-ready field list and batch URL file generation.
- `P1` Microsoft Graph delegated draft creation with attachments and open link.
- `P1` Reporting-channel administration with verification dates.
- `P2` Optional schema-constrained LLM rewrite and summarization.

## Epic F — Team operation

- `P0` PostgreSQL persistence and migrations for shared deployment.
- `P0` Audit events for human and automated state changes.
- `P0` Entra ID or approved SSO and basic roles.
- `P0` Central secret management and encrypted evidence storage.
- `P1` Internal notification adapter.
- `P1` Retention, legal hold, and restricted victim-data workflow.

## Epic G — Campaigns and measurement

- `P1` Manual campaign grouping and campaign export.
- `P1` Proposed correlations with provenance and confirmation.
- `P1` Operational metrics for interaction time, due actions, and mitigation.
- `P2` Approved enrichment providers and campaign discovery.

## Suggested implementation increments

### Increment 1 — Usable local slice

Case intake, safe normalization, local evidence manifest, qualification model, deterministic draft, and simple web UI. No network collection is required to demonstrate the end-to-end human workflow.

### Increment 2 — Evidence-producing collector

DNS, RDAP, HTTP, TLS, job execution, isolated screenshot, persistence, and ZIP verification.

### Increment 3 — Cadence and Outlook

Actions, scheduler, diff, reporting catalogue, Graph draft creation, SSO, and shared deployment.

### Increment 4 — Campaign intelligence

Correlation, optional enrichment, optional LLM assistance, and dashboards.

## Definition of done

Every story that processes target-controlled data requires:

- unit tests for allowed and denied cases;
- explicit size/time/network limits;
- structured failure behavior;
- no sensitive payload in logs;
- documentation of generated artifacts;
- review against the threat model;
- synthetic test data only.

