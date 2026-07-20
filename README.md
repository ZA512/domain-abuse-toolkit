# Domain Abuse Toolkit

Domain Abuse Toolkit is an internal-first case management and evidence-preparation tool for suspected phishing, brand impersonation, and fraudulent websites.

The product is designed to turn a suspicious URL into a traceable case with evidence, recommended actions, human-approved message drafts, deadlines, and exportable records. Python provides the collection engine; a web interface is the primary operator experience.

> This public repository must not contain real evidence, personal data, credentials, internal procedures, customer information, or confidential brand material.

## Product direction

The MVP focuses on five outcomes:

1. Create a case from a URL with minimal operator input.
2. Collect and preserve passive technical observations safely.
3. Prepare an integrity-verifiable evidence package.
4. Generate approved, editable action and email drafts.
5. Track owners, deadlines, checks, reminders, and escalations.

External messages and forms always require human validation. Automatic sending and automatic form submission are intentionally outside the MVP.

## Repository status

This foundation currently includes:

- a product requirements document and MVP backlog;
- an architecture, data model, operator journey, and security model;
- a small FastAPI application with case intake and draft generation;
- deterministic message templates;
- URL normalization and public-network safety checks;
- a local evidence store with SHA-256 manifests;
- restart-safe local case persistence with integrity verification;
- action completion, automatic workflow state and immutable local event history;
- human qualification revisions with confirmed criticality and override rationale;
- unit tests for the first safety-critical behaviors.

Network collection, browser capture, shared database persistence, scheduling, Microsoft Graph, and optional LLM integration are represented in the design but remain feature-gated until implemented and reviewed.

## Quick start

### Windows one-click test

On the current Windows/WSL development setup:

1. Double-click `START_TOOLKIT.cmd` to start the local application and open it in the default browser.
2. Double-click `RUN_TESTS.cmd` to install development dependencies and run lint plus unit tests.
3. Stop the application with `STOP_TOOLKIT.cmd`, `Ctrl+C` in the visible server window, or by closing that window.

The launchers keep the Python environments and private pilot cases under the WSL user profile, outside this public Git repository. See the [local testing guide](docs/testing-guide.md).

### Manual Python setup

Requirements: Python 3.12 or later.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
uvicorn domain_abuse_toolkit.main:app --reload --host 127.0.0.1 --port 8080
```

On Windows PowerShell, activate the environment with:

```powershell
.venv\Scripts\Activate.ps1
Copy-Item .env.example .env
uvicorn domain_abuse_toolkit.main:app --reload --host 127.0.0.1 --port 8080
```

Open `http://127.0.0.1:8080`.

Run checks with:

```bash
ruff check .
pytest
```

## Safety defaults

- The service binds to localhost by default.
- Network collection, screenshots, external APIs, LLMs, and Microsoft Graph are off by default.
- Private, loopback, link-local, multicast, reserved, and unspecified IP targets are rejected.
- Redirect targets must be revalidated before a collector follows them.
- Evidence and private directories are ignored by Git.
- Generated text is a draft and cannot trigger an external action.

Read [the security and evidence model](docs/security-and-evidence.md) before enabling any network collector.

## Documentation

- [Product requirements v0.2](docs/PRD_v0.2.md)
- [Operator journey](docs/operator-journey.md)
- [Architecture](docs/architecture.md)
- [Data model](docs/data-model.md)
- [Security and evidence](docs/security-and-evidence.md)
- [MVP backlog](docs/mvp-backlog.md)
- [Local testing guide](docs/testing-guide.md)

## License

No open-source license has been selected yet. Until a license is added, copyright law applies by default.
