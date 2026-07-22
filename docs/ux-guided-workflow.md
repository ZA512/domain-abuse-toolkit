# Guided operator workflow

## Problem to solve

The functional local pilot currently exposes most case tools on one long page. The content is visually consistent, but the operator must infer the process, locate the next action, and distinguish finished work from optional or future work. The final UX must present a workflow rather than a catalogue of features.

## Chosen direction

Use a compact step rail on desktop and a horizontal stepper on small screens. Only the current workspace is expanded by default; completed and future steps remain visible as concise summaries.

1. **Case** — target, brand context, integrity and evidence export.
2. **Evidence** — passive jobs, status, failures, snapshots and evidence count.
3. **Qualification** — human observations and confirmed criticality.
4. **Reports** — channel choice, summaries, email/form drafts and human submission record.
5. **Follow-up** — next check, response, escalation, mitigation and closure.

Every step displays exactly one derived state:

- `to_do` — operator input is required now;
- `in_progress` — a job or incomplete decision exists;
- `complete` — the required outcome is recorded;
- `limited` — the core outcome is usable, while bounded or optional evidence is missing;
- `attention` — a concrete error or overdue action requires review;
- `scheduled` — no work is required before the displayed UTC date.

A disabled optional capability is explained inside its step and does not block the next human task. The active step is derived from case facts, collection jobs and immutable events. Legacy action flags never override a recorded qualification or submission.

## Interaction principles

- Lead with one **Next best action** at the top of the case.
- Derive progress from case facts and immutable events; never ask the operator to maintain a second progress checklist.
- Keep one primary button per step and visually demote optional tools.
- Replace explanatory paragraphs with short labels; put definitions, safety details and examples in contextual help popovers.
- Keep evidence integrity, criticality, case state and the next due date visible at all times.
- Allow direct links to each step and preserve keyboard navigation.
- Show completed-step summaries without reopening their full forms.
- Reserve the audit trail and technical diagnostics for a secondary drawer.

## Implemented first pass

The case page now uses the five-step rail, a single derived next-best action, one expanded workspace, compact completed-state summaries, a permanent evidence-export action, and a secondary journal. A new case opens on Evidence before Qualification. Collection launches open a live progress dialog, may continue in the background, and end with an explicit complete, usable-with-limits, or action-required outcome.

## Acceptance criteria for the UX pass

- A first-time operator can identify the next required action in under five seconds.
- The case stage and the next deadline remain visible without scrolling.
- Completed, blocked and scheduled steps are distinguishable without opening them.
- Only one detailed workspace is expanded on initial load.
- No existing audit, safety confirmation, evidence or human-approval control is removed.
- The responsive layout remains usable without horizontal page scrolling.
