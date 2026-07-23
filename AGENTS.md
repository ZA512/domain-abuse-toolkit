# Project guidance

## UX/UI doctrine

Domain Abuse Toolkit is an operational tool, not a documentation surface.

Every operational screen must let a regular operator answer quickly:

1. What is the current state?
2. Do I need to act now?
3. What is the single next action?
4. When is it due?
5. What happens after that?
6. Is anything blocked or abnormal?

Use a task-first, progressive-disclosure and exception-driven hierarchy:

`Now → Next → Later → Details on demand`

- Give each page one clear centre of gravity and normally one dominant action.
- Keep decision-critical state and deadlines visible without relying on hover, colour or
  tooltips.
- Visually demote completed work while keeping it accessible for traceability.
- Move explanation, learning content, history and technical evidence into `details`,
  drawers or dedicated views when they are not needed for the current decision.
- Never remove business, legal, security or audit information to obtain a minimalist look.
- Do not repeat the same state in several competing cards without a concrete operational need.
- Preserve keyboard access, responsive layouts, empty/error states, confirmations,
  authorisations and human validation.
- Prefer scan-friendly labels and short summaries over permanent explanatory paragraphs.
- Optimise the default view for a regular operator; keep onboarding help available on demand.
- Allow investigation and audit views to remain intentionally denser than operational views.

Before changing an operational screen, classify its content as:

- immediate action;
- essential state;
- future event or deadline;
- useful context;
- explanation or help;
- technical detail or audit.

Rebuild the hierarchy from that classification. Do not merely rearrange existing cards.
The detailed doctrine and page classifications live in
`docs/ux-ui-doctrine.md`.

