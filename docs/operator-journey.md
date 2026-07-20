# Operator journey

## Design objective

The interface should answer three questions without forcing the operator to reconstruct the case:

1. What do we know?
2. What must a human validate?
3. What is the next action, and when is it due?

## Screen 1 — New case

Required fields:

- suspicious URL;
- brand profile.

Optional fields are collapsed: detection source, campaign, urgency, and notes.

The primary button is **Create case and collect evidence**. Before execution, the page states which capabilities are enabled and that no email or form will be submitted.

## Screen 2 — Collection progress

Case creation is immediate. Collector cards update independently:

- target safety;
- DNS;
- registration/RDAP;
- HTTP and redirects;
- TLS;
- IP/ASN;
- visual capture;
- optional enrichment.

Each card reports `queued`, `running`, `complete`, `partial`, `failed`, or `skipped`. A failed optional collector does not fail the case.

## Screen 3 — Validation desk

The operator sees the screenshot and concise observations before raw data.

The mandatory checklist asks only questions that require judgment:

- Is the selected brand represented?
- Are copied brand, product, or visual elements visible?
- Is a login, personal-data form, or payment path offered?
- Are victims or transactions known?
- Is this related to another case or campaign?

The application displays its proposed criticality and the exact contributing rules. The operator confirms or overrides it with a reason.

## Screen 4 — Action cockpit

Actions are ordered by due date and risk, not by technical actor.

Each card contains:

- recommended action and reason;
- organization/channel;
- due date and owner;
- required evidence readiness;
- **Prepare**, **Open**, **Record result**, and **Defer** controls.

Possible examples:

- prepare a registrar draft;
- copy a browser-protection description;
- download a multi-URL text file;
- open an official reporting form;
- request internal legal review;
- schedule a new check.

## Screen 5 — Draft workspace

The draft workspace shows:

- recipients or destination;
- subject;
- editable body;
- facts used;
- missing placeholders;
- selected attachments;
- template and clause versions.

Primary actions:

- copy subject;
- copy body;
- create Outlook draft;
- download attachments;
- return for review.

There is no **Send** button in the MVP.

## Screen 6 — Record submission

After the operator completes the external action, the application asks for:

- completion date and time;
- channel;
- destination;
- external ticket/reference;
- acknowledgement or screenshot;
- notes.

Recording completion schedules the next action according to the active workflow rule.

## Screen 7 — Follow-up review

At the due date, the application launches or offers a new snapshot. The page leads with changes:

- active/inactive state;
- DNS and IP changes;
- redirects or content changes;
- certificate changes;
- replies and elapsed time.

The operator can prepare a reminder, escalate, mark mitigated, transfer, or close.

## Screen 8 — Campaign view

The campaign view presents:

- confirmed and proposed related cases;
- shared technical indicators with confidence and provenance;
- active versus mitigated domains;
- consolidated action history;
- campaign-level draft and export.

Correlation suggestions never merge cases automatically.

