# UX/UI doctrine

## Purpose

Domain Abuse Toolkit is an operational tool. Its primary surfaces must support decisions and
actions; they must not read like documentation.

An operator opening a page should understand in a few seconds:

- the current state;
- what has already been done;
- what needs attention now;
- what will happen next;
- known deadlines and future events;
- any blocker or anomaly.

The default mental model is:

`State → Now → Next → Later → Details`

When chronology is more useful:

`Completed → In progress → Action required → Upcoming`

These labels are a model, not mandatory visible headings.

## Principles

### Task-first

The primary operational action dominates the page. State supports the decision and must not
compete visually with that action.

### Progressive disclosure

Decision-critical information stays visible. Explanation, onboarding, history and technical
evidence remain available at a second level through `details`, a drawer or a dedicated view.

### Exception-driven

The interface gives attention to overdue actions, failures, limitations and blockers. Normal,
completed and waiting states progressively lose visual weight.

### Information preservation

Simplification never means deletion. Business, technical, legal, security and audit
information must retain an explicit access path.

### Accessibility

Important information never depends only on colour, hover or a tooltip. Controls remain
keyboard usable, responsive and understandable to assistive technology.

### Regular-operator priority

The default view is optimised for recurring use. Learning content and detailed explanations
remain available on demand.

## Required classification before implementation

Every page redesign starts by assigning each existing item to one category:

1. **Immediate action** — input or decision expected now.
2. **Essential state** — facts needed to choose or understand that action.
3. **Future event / deadline** — scheduled work, reminders and known checks.
4. **Useful context** — supporting facts that improve confidence.
5. **Explanation / help** — definitions, onboarding and safety explanations.
6. **Technical detail / audit** — immutable events, raw evidence, identifiers and diagnostics.

Items may move to a secondary level, but no item disappears without a documented destination.

## Home page classification

| Existing information | Classification | Destination |
| --- | --- | --- |
| Cases requiring validation, reporting, follow-up or overdue checks | Immediate action | Primary work queue, first on page |
| Case state, criticality, availability and anomaly | Essential state | Compact queue row |
| Next action and due date | Immediate action / deadline | Dominant text in each queue row |
| Monitoring and technical-check dates | Future event / deadline | Secondary line in queue row |
| Waiting cases with no action due | Essential state | Separate quieter queue group |
| Closed cases | Context / audit | Collapsed archive, searchable and reopenable |
| Create-case form | Occasional action | Collapsed secondary action near page heading |
| Network/rendering/LLM/Graph capabilities | Context / help | Collapsed tool-status disclosure |
| Creation safety contract and persistence explanation | Explanation / help | Inside the create-case disclosure |
| Case identifier, exact URL and creation date | Technical detail / audit | Secondary metadata in queue row |

The home page centre of gravity is the operational queue, regardless of the number of cases.

## Case page classification

| Existing information | Classification | Destination |
| --- | --- | --- |
| Current case state, target, criticality, availability and blocker | Essential state | Compact command/header area |
| Derived next best action and its deadline | Immediate action | Single dominant action surface |
| Current workflow step | Essential state | Compact step rail |
| What follows the current action | Future event / deadline | Concise “next/later” strip |
| Next technical and automatic monitoring checks | Future event / deadline | Future strip; configuration stays secondary |
| Completed workflow steps | Useful context / audit | Demoted step summaries |
| Monitoring configuration and authorisation | Useful context / safety | Disclosure within Follow-up |
| Submission records | Useful context / audit | Concise recent result plus disclosure |
| Meaning of UP/DOWN and scheduler behaviour | Explanation / help | Details/help disclosure |
| Snapshots, evidence differences and collection limits | Technical detail / audit | Evidence workspace |
| Integrity status, event history and manual action log | Technical detail / audit | Journal/details disclosure |
| Close/reopen case controls | Immediate lifecycle action when chosen | Secondary case-management disclosure with confirmation |

## Follow-up page target hierarchy

The Follow-up workspace must answer:

- **Where are we?** Case state and last known availability.
- **Do I need to act?** Explicit “now”, “planned” or “waiting” state.
- **What?** One next process action.
- **When?** Due date shown with the action.
- **What happens next?** Next technical/automatic check and later escalation context.

Monitoring configuration, explanatory copy and submission history remain accessible but must
not compete with the active process action.

## UX validation scenario

After every relevant change, open a case as if it were the first visit of the day and answer,
without reading every paragraph:

1. Where are we?
2. Must I do something?
3. What exactly?
4. When?
5. What happens next?

If an answer requires scanning several competing cards or reading long paragraphs, the
hierarchy is not finished.

