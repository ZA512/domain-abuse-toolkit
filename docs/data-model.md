# Data model

## Design principles

- A case is not a spreadsheet row.
- A collection is an immutable snapshot, not an update in place.
- An action is a first-class event with an owner and evidence.
- Original artifacts never become derived artifacts through mutation.
- Proposed machine classifications remain distinguishable from confirmed human decisions.

## Primary entities

### Case

| Field | Purpose |
|---|---|
| `id` | Stable public-safe identifier such as `DAT-2026-000001` |
| `state` | Current workflow state |
| `brand_profile_id` | Legitimate entity being protected |
| `exact_input` | Exact submitted URL/domain |
| `normalized_url` | Canonicalized URL for collection |
| `host` | Normalized ASCII host |
| `registrable_domain` | Public-suffix-aware domain |
| `criticality_proposed` | Rule-engine proposal |
| `criticality_confirmed` | Human decision |
| `owner_id` | Current responsible user/team |
| `campaign_id` | Optional confirmed campaign |
| `created_at`, `updated_at` | UTC audit fields |

### Snapshot

One collection run for a case. It records trigger (`manual` or `scheduled`), policy version, tool version, start/end, status, the set of collector results, its previous snapshot, normalized changes, and the next operator review date. Snapshots are append-only. A scheduled availability snapshot contains only bounded DNS/HTTP/TLS collectors and requires an active case-level authorization.

### Snapshot change

An immutable grouped difference between two successive snapshots. It records collector, category, field or record type, previous values, current values, change type, and whether the field is operationally important. Observation ordering and DNS TTL drift alone do not create a change.

### Observation

A structured fact or failed observation, with category, name, value, confidence where applicable, source collector, provenance, and snapshot.

### Artifact

Metadata for a stored file: digest, size, media type, storage reference, source, original/derived status, derivation parent, redaction status, and retention class.

### Qualification

Human answers to the review checklist, proposed/confirmed criticality, rationale, reviewer, and timestamp. New reviews create immutable revisions; the local pilot replays those revisions from the integrity-checked evidence manifest.

### Action

| Field | Purpose |
|---|---|
| `type` | Report, reminder, check, escalation, review, close, transfer |
| `status` | Proposed, ready, in progress, completed, deferred, cancelled |
| `target_party_id` | Registrar, registry, host, platform, authority, internal team |
| `owner_id` | Responsible user/team |
| `due_at` | Deadline |
| `completed_at` | Completion time |
| `reason` | Rule or human rationale |
| `external_reference` | Ticket or acknowledgement identifier |
| `proof_artifact_id` | Evidence that the action occurred |
| `workflow_rule_version` | Rule that proposed the action |

### Draft

An immutable generated revision containing destination, subject, body, language, template version, clause versions, fact inputs, missing placeholders, selected attachments, and optional external draft ID/link.

### Party and reporting channel

A party represents an organization or internal team. A reporting channel represents a versioned URL, email, or procedure for a particular abuse and scope combination.

### Submission event

An immutable operator confirmation that an external report was sent. It records the selected channel, destination, external reference, factual notes, occurrence time, and calculated follow-up date. It never implies that the toolkit sent or that the recipient accepted the report.

### Monitoring event

An immutable operator decision that enables, updates, or disables recurring availability
checks for one case. It records the interval and decision time. Enabling requires an
explicit continuous-authorization confirmation. The current case projection also keeps
the enabled state, interval, and authorization time used to calculate the next due check.

### Case lifecycle event

An immutable operator decision that closes or reopens a case. It records the previous and
resulting state, resolution, operator, reason and timestamp. Closing never deletes evidence or
history and disables recurring monitoring; reopening derives the active state again from the
recorded qualification and submissions, but does not restore network authorization.

### Campaign

A confirmed grouping of cases with name, owner, state, criticality, and notes. Proposed correlations are stored separately until accepted.

### Correlation

A proposed or confirmed relationship between two cases or targets. It records indicator type, value or digest, confidence, provenance, and reviewer disposition.

### Audit event

Append-only actor, action, object type/ID, time, request correlation ID, and safe metadata. Sensitive evidence content does not belong in the audit log.

## Key relationships

```text
Brand profile 1---* Case *---0..1 Campaign
                       |
                       +---* Snapshot ---* Observation
                       |          |
                       |          +---* Artifact
                       +---* Qualification revision
                       +---* Action ---0..1 Draft
                       |       |
                       |       +---0..1 proof Artifact
                       +---* Submission event
                       +---* Case lifecycle event
                       +---* Audit event

Party 1---* Reporting channel
```

## Migration from a tracking workbook

The legacy flat row can be imported by mapping stable case facts to `Case`, technical columns to an initial `Snapshot`, and each dated report/relance/escalation column to a separate `Action`.

Combined strings such as `Yes - 2026-01-01` must be split into status, timestamp, actor, channel, proof, and external reference. Import should preserve the original workbook row as a source artifact for auditability.
