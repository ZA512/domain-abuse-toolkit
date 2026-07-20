# Product Requirements Document — Domain Abuse Toolkit

| Field | Value |
|---|---|
| Document version | 0.2 draft |
| Product stage | MVP definition |
| Audience | Security operations, legal/brand reviewers, customer protection teams |
| Repository classification | Public-safe; synthetic examples only |
| Product principle | Automate preparation and follow-up, preserve human authority over external actions |

## 1. Product summary

Domain Abuse Toolkit is a case-management and evidence-preparation application for suspected phishing, fraudulent shops, and brand impersonation.

An operator submits a URL. The application creates a case, performs approved passive collection, preserves observations as verifiable evidence, recommends the next actions, prepares editable drafts, and tracks the case until mitigation or transfer to another process.

The operator experience is web-first. The underlying Python services remain callable from a CLI or worker so that collection can be tested, automated, and reused independently of the interface.

## 2. Problem

Current takedown work usually requires an operator to repeat the same sequence across multiple tools:

- normalize a URL and identify the registrable domain;
- query DNS, RDAP, TLS, HTTP, IP, and network ownership data;
- collect visual evidence without interacting with the suspected site;
- determine which external party is relevant for the observed harm;
- find the current reporting channel;
- rewrite similar explanations and emails;
- remember follow-up dates and repeat the technical checks;
- assemble evidence and action history for escalation.

The work is slow, inconsistent, difficult to hand over, and particularly error-prone during multi-domain campaigns.

## 3. Product goals

### 3.1 Operator goals

- Create a complete initial case with less than five minutes of operator interaction.
- Reduce required data entry to facts that cannot be collected safely or inferred reliably.
- Make the next action and its due date visible at all times.
- Prepare an Outlook draft or a form-ready payload in one click.
- Compare new observations with previous snapshots automatically.
- Produce a reusable evidence package without manual file assembly.

### 3.2 Assurance goals

- Preserve originals and distinguish them from derived or annotated artifacts.
- Maintain an auditable history of automated and human actions.
- Prevent the collector from reaching internal or otherwise prohibited network targets.
- Keep external sending, form submission, and legal qualification under human control.
- Operate without optional commercial APIs or LLMs.

### 3.3 Team goals

- Allow case handover without reconstructing the investigation.
- Group related domains into a campaign.
- Measure overdue actions, time to qualification, time to first report, and time to mitigation.
- Support role-based access and central retention in a later deployment phase.

## 4. Non-goals for the MVP

- Sending email automatically.
- Submitting third-party forms automatically.
- Circumventing CAPTCHA, WAF, authentication, or anti-bot controls.
- Crawling payment funnels or submitting personal, authentication, or payment data.
- Performing vulnerability scanning or intrusive testing.
- Making a final legal determination.
- Using an LLM as a source of technical facts or as an autonomous agent.
- Replacing legal dispute mechanisms such as UDRP, URS, litigation, or law-enforcement processes.

## 5. Users and permissions

### Operator

Creates cases, validates observations, prepares reports, records submissions, and performs checks.

### Reviewer

Validates brand, legal, or communications language and can approve a draft for manual sending.

### Case owner

Assigns responsibility, changes criticality, authorizes escalation, and closes or transfers cases.

### Administrator

Manages brands, approved clauses, reporting channels, workflow rules, integrations, retention, and access.

The initial local MVP may collapse these roles into one authenticated user, but the data model must retain actor and role fields.

## 6. Core operator journey

1. Submit the exact suspicious URL and select a brand profile.
2. Confirm whether network collection is authorized for the case.
3. Create the case immediately; collection runs as a separate job.
4. Review the collected observations and any explicit failures.
5. Answer the short qualification checklist.
6. Review the proposed criticality and workflow.
7. Create an Outlook draft, copy a form payload, or open the official reporting page.
8. Record proof of submission and any external reference.
9. Let the application schedule the next check.
10. Review the diff, perform a reminder or escalation, and eventually close or transfer the case.

See [operator-journey.md](operator-journey.md) for screen-level detail.

## 7. Functional requirements

### FR-01 — Case intake

The application must accept:

- an exact URL or domain;
- a brand profile and legitimate reference URL;
- the source of detection;
- a suspicion category;
- optional urgency, campaign, and internal notes.

It must preserve the exact submitted value and separately store normalized URL, host, registrable domain, path, query, and internationalized-domain representations.

### FR-02 — Safe target validation

Before any network request, the system must:

- accept only approved schemes;
- reject embedded credentials and invalid ports;
- resolve the target and reject non-public addresses;
- repeat this check for every redirect and browser navigation;
- enforce response-size, redirect-count, and timeout limits;
- record the rejection as an observation rather than silently failing.

### FR-03 — Passive technical collection

When enabled, collectors should gather:

- A, AAAA, NS, MX, TXT, CNAME, SOA, and CAA records;
- RDAP response, registrar, registry, statuses, events, and abuse contacts;
- exact HTTP request URL, final URL, redirect chain, status, selected headers, content type, raw response hash, and bounded body;
- TLS protocol, certificate chain where available, subject, issuer, SAN, validity, and fingerprint;
- visible IP addresses, ASN, network organization, and public abuse contact sources;
- provider hints with evidence and confidence rather than an unqualified provider assertion.

Every collector returns structured data, provenance, start/end time, version, and an explicit success, partial, skipped, or failed status.

### FR-04 — Isolated visual capture

Browser capture must run in an ephemeral isolated worker with:

- no personal browser profile;
- no access to private networks or host services;
- downloads, clipboard, notifications, geolocation, camera, and microphone denied;
- no form submission, payment interaction, or CAPTCHA bypass;
- desktop full-page capture and an optional mobile viewport;
- raw screenshot plus a separately annotated derivative;
- bounded navigation time and resource size.

### FR-05 — Evidence integrity

Each evidence artifact must have:

- a stable identifier;
- case and snapshot identifiers;
- collection timestamp in UTC;
- collector and tool version;
- media type and byte size;
- SHA-256 digest;
- source URL or query where relevant;
- original/derived classification;
- derivation reference for annotated, redacted, or converted artifacts.

The case export must include a machine-readable manifest. Optional later formats include WARC/WACZ and trusted timestamping.

### FR-06 — Qualification

The operator checklist must capture at least:

- brand or identity elements observed;
- copied products, text, or images;
- credential or personal-data collection;
- payment or checkout behavior visibly offered;
- reported victims or transactions;
- related domains or recurrence;
- public availability at the time of review.

The application may propose a criticality with its contributing rules. A human must confirm it.

### FR-07 — Routing and action plan

The workflow engine must create action records based on:

- harm category;
- TLD and relevant policy family;
- criticality;
- active user risk;
- campaign status;
- completed reports, responses, and elapsed time.

Rules must be versioned and explain why an action was proposed. A fixed thirty-day sequence may be provided as a baseline, but critical phishing cases must support parallel action at the initial stage.

### FR-08 — Reporting-channel catalogue

The catalogue must hold:

- organization and role;
- official reporting URL or abuse address;
- supported abuse types and TLD scope;
- required fields and recommended attachments;
- last verification date and source;
- authentication, CAPTCHA, or batch-upload notes;
- active, deprecated, or review-needed status.

Links must not remain unversioned constants in application code.

### FR-09 — Deterministic message drafts

The application must assemble French and English drafts from approved clauses and validated case facts.

Draft generation must support:

- initial registrar, registry, infrastructure, and internal-review messages;
- reminders and escalations with action history;
- short descriptions for external forms;
- campaign-level lists and summaries;
- explicit placeholders for missing human-owned information.

Every output is marked as a draft and records the template version and inputs.

### FR-10 — Outlook integration

The baseline must offer copy buttons and a percent-encoded `mailto:` fallback.

When Microsoft Graph is enabled and approved, the system may create—but not send—an Outlook draft with recipients, subject, HTML/text body, and selected evidence attachments. It must store the draft identifier and open link without storing mailbox contents unnecessarily.

### FR-11 — Manual form assistance

For form-only channels, the application must:

- show the exact URL to report;
- prepare each expected text value;
- provide one-click copy controls;
- generate batch text or CSV files where accepted;
- open the official reporting page in a new browser context;
- require the operator to record submission proof and reference.

### FR-12 — Actions, deadlines, and reminders

Each action must have status, owner, due date, completion time, channel, target party, proof, external reference, and notes.

The system must show overdue and upcoming work. A scheduler may create check jobs and internal notifications, but it must not perform external communications autonomously.

### FR-13 — Snapshot comparison

A new collection must compare DNS, IP, ASN, HTTP, redirect, TLS, provider, screenshot hash, and availability with the previous snapshot.

The user should see changes first and unchanged details on demand.

### FR-14 — Campaigns

Cases may be grouped manually or by proposed correlations such as shared IP, nameserver, certificate, redirect, content hash, tracker, or naming pattern.

Automated correlation remains a proposal until confirmed by an operator.

### FR-15 — Export

The system must export:

- case summary;
- structured JSON;
- action history;
- evidence manifest;
- approved message drafts;
- selected original and derived artifacts;
- ZIP package.

PDF, DOCX, XLSX, WARC, and WACZ are later adapters built from the same canonical data.

### FR-16 — Optional LLM assistance

The product must function fully without an LLM.

If enabled, an LLM may summarize validated observations, translate or shorten a draft, and produce a schema-constrained proposed classification. It must not call tools, choose recipients, send messages, change case state, or treat target content as instructions.

Provider, model, prompt version, structured response, and human disposition must be logged.

## 8. Case states

The initial state machine is:

```text
new
  -> collecting
  -> needs_validation
  -> ready_to_report
  -> waiting_external
  -> follow_up_due
  -> escalated
  -> mitigated
  -> closed

Any active state may also become blocked, transferred, or false_positive.
```

State changes must be event-driven and auditable. Completion of one action must not overwrite the history of previous actions.

## 9. Non-functional requirements

### Security

- Bind to localhost by default.
- Require SSO and role-based access before shared deployment.
- Encrypt secrets and private evidence at rest using organization-approved controls.
- Sanitize logs and prohibit response bodies, cookies, tokens, and personal data in routine logs.
- Apply SSRF and DNS-rebinding controls at every network boundary.
- Treat browser and LLM components as separate, low-trust services.

### Reliability

- Isolate collector failures by target and collector.
- Make jobs idempotent and retry only bounded transient errors.
- Preserve partial results and explicit error evidence.
- Version schemas, templates, workflow rules, and collectors.

### Performance

- Case creation response: under two seconds without waiting for collection.
- Base collection target: under sixty seconds for one domain when external services respond normally.
- UI interactions after initial load: under one second for local operations.

### Accessibility and usability

- Keyboard-operable interface and visible focus states.
- Do not communicate criticality or status through color alone.
- Display human-readable explanations before raw JSON.
- Keep required operator decisions to a small review checklist.

### Portability

- Windows is a first-class operator platform.
- Development and workers support Windows, Linux, and containers.
- Shared deployments run in an organization-controlled container or VM environment.

## 10. MVP acceptance criteria

The MVP is accepted when an authorized operator can:

1. Create a case from an exact URL.
2. See normalization and safety-validation results.
3. Run the approved passive collectors as a background job.
4. Review structured observations and explicit failures.
5. Complete the short qualification checklist and confirm criticality.
6. Generate at least one bilingual deterministic message draft.
7. Copy the form payload or create an Outlook draft when Graph is configured.
8. Record a submission with evidence and external reference.
9. Receive a due-action reminder and launch a new snapshot.
10. Review changes and export a ZIP with a valid SHA-256 manifest.

The MVP fails acceptance if it can send externally without a separate human action, follows a redirect to a non-public address, silently drops collector failures, or permits evidence directories to be committed by the documented workflow.

## 11. Success metrics

- Median operator interaction time from URL to validated initial package.
- Median number of manual copy/paste operations per initial report.
- Percentage of cases with complete initial evidence.
- Percentage of actions completed before their due date.
- Median time from detection to first validated report.
- Median time from detection to mitigation.
- Percentage of drafts accepted with no substantive rewrite.
- Percentage of cases grouped into confirmed campaigns.
- False-positive and reopened-case rates.

## 12. Delivery sequence

### Foundation

Public-safe documentation, case schema, intake UI, deterministic drafts, URL safety, evidence manifest, and tests.

### MVP collection

Background jobs, DNS/RDAP/HTTP/TLS collectors, isolated capture, database persistence, action timeline, and ZIP export.

### Team workflow

Microsoft Entra ID, role-based access, scheduler, notifications, Outlook draft creation, shared evidence storage, and reporting-channel administration.

### Campaign intelligence

Snapshot diff, campaign correlation, optional enrichment APIs, optional LLM assistance, and operational dashboards.

## 13. Open decisions

- Shared deployment location and identity provider approval.
- Canonical evidence store and retention policy.
- Whether the public repository remains the code home or mirrors a private internal repository.
- Microsoft Graph consent model and shared-mailbox requirements.
- Legal-approved clause library and approval workflow.
- Permitted external enrichment services and data-processing terms.
- Whether trusted timestamping or signed WACZ is required.
- License for the public repository.

