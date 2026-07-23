# Operator journey

## Design objective

The interface should answer three questions without forcing the operator to reconstruct the case:

1. What do we know?
2. What must a human validate?
3. What is the next action, and when is it due?

## Screen 1 — Operational work queue

The default landing page prioritizes recurring work over creation. It groups active cases into:

- attention required now;
- waiting for an external event;
- other active work.

Rows lead with the current action and due date, supported by case state, criticality and last
availability. Search covers brand, domain, case identifier and exact URL. Closed cases remain in
a collapsed archive.

Creating a case is an occasional secondary action disclosed from this screen.

## Screen 2 — New case

Required fields:

- suspicious URL;
- brand profile.

Optional fields are collapsed: detection source, campaign, urgency, and notes.

The primary button is **Create case and collect evidence**. Before execution, the page states which capabilities are enabled and that no email or form will be submitted.

## Screen 3 — Collection progress

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

## Screen 4 — Validation desk

The operator sees the screenshot and concise observations before raw data.

The mandatory checklist asks only questions that require judgment:

- Is the selected brand represented?
- Are copied brand, product, or visual elements visible?
- Is a login, personal-data form, or payment path offered?
- Are victims or transactions known?
- Is this related to another case or campaign?

The application displays its proposed criticality and the exact contributing rules. The operator confirms or overrides it with a reason.

## Screen 5 — Reporting priorities

Reporting actions are ordered by operational importance: registrar first, user-protection
services second, TLD registry third, and ICANN contractual escalation last. Contextual
authority channels remain available separately.

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

## Screen 6 — Draft workspace

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

## Screen 7 — Record submission

After the operator completes the external action, the application asks for:

- completion date and time;
- channel;
- destination;
- external ticket/reference;
- acknowledgement or screenshot;
- notes.

Recording completion schedules the next action according to the active workflow rule.

The local pilot implements the channel, destination, reference, notes, immutable event, and follow-up date. Proof attachments and operator identity are reserved for the authenticated shared deployment.

## Screen 8 — Follow-up review

The page leads with the latest bounded HTTP availability signal and the exact next
process action. `UP` means an HTTP response was received; it does not prove that the
fraudulent content is still present. `Probably DOWN` means the HTTP connection failed
and must be confirmed by a human.

The standard high-severity cadence is:

- initial registrar report at J0/J1;
- first registrar reminder at J+7 if the site remains active;
- strengthened reminder and escalation preparation at J+14/J+15;
- TLD registry escalation at J+15/J+21;
- ICANN, authority, or legal escalation at J+21/J+30;
- closure or transfer at J+30.

The operator can separately authorize recurring DNS/HTTP/TLS checks for the case.
The local scheduler runs while the application is open, preserves its configuration,
and catches up an overdue check after restart. It does not run RDAP, screenshots,
JavaScript, forms, or external messages.

At the due date, the application launches or offers a new snapshot. The page leads with changes:

- active/inactive state;
- DNS and IP changes;
- redirects or content changes;
- certificate changes;
- replies and elapsed time.

The operator can prepare a reminder, escalate, mark mitigated, transfer, or close.

Case management is secondary to the current task but always reachable from the case header.
Closing requires a resolution, operator and reason, keeps all evidence available, removes the
case from the active queue and disables scheduled monitoring. Reopening is audited and requires
new monitoring authorization.

## Screen 9 — Campaign view

The campaign view presents:

- confirmed and proposed related cases;
- shared technical indicators with confidence and provenance;
- active versus mitigated domains;
- consolidated action history;
- campaign-level draft and export.

Correlation suggestions never merge cases automatically.
