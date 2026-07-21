# Architecture

## Recommended shape

The application is web-first but keeps collection and export logic independent from the web layer.

```text
Operator browser
      |
      v
Web application / API
  |       |        |
  |       |        +--> Template and workflow engine
  |       +-----------> Relational database
  +-------------------> Job queue
                            |
              +-------------+-------------+
              |                           |
       Passive collector worker     Isolated browser worker
              |                           |
              +-------------+-------------+
                            |
                      Evidence store

Optional adapters: Microsoft Graph, notifications, enrichment APIs, local or hosted LLM
```

## Components

### Web application

- Case intake and review UI.
- JSON API for cases, snapshots, actions, drafts, and exports.
- Authentication and authorization in shared deployments.
- No long-running collection inside request handlers.

FastAPI is suitable for the service layer. Server-rendered Jinja templates keep the first UI small; a richer frontend can replace them later without coupling collector logic to the browser.

### Job queue

Collection, screenshot, diff, archive, and scheduled-check jobs must be asynchronous and idempotent. The queue implementation is deliberately not fixed in the foundation. A production decision should consider Redis availability, operational ownership, retries, and job observability.

### Passive collector worker

Collectors implement a common result contract:

```json
{
  "collector": "http",
  "version": "1.0",
  "status": "complete",
  "started_at": "2026-01-01T12:00:00Z",
  "finished_at": "2026-01-01T12:00:01Z",
  "observations": [],
  "artifacts": [],
  "errors": []
}
```

Each redirect or secondary target passes through the same network policy as the initial target.

The local pilot now executes bounded DNS/HTTP/TLS/RDAP jobs in a small in-process worker pool after an explicit operator action. The web transport connects directly to a validated public IP while preserving Host/SNI and repeats resolution and policy checks for every redirect. RDAP service discovery uses the official IANA bootstrap over validated HTTPS and keeps only operational registration fields in the interface. Raw DNS messages, bounded textual bodies, leaf certificates, RDAP JSON and the final snapshot event are immutable evidence. This executor is intentionally a pilot mechanism; a shared deployment must move jobs to the isolated queue/worker boundary shown above.

### Browser worker

Rendered capture is separated because executing hostile JavaScript has a different risk profile from DNS or RDAP queries. The worker uses an ephemeral browser context, network egress restrictions, strict limits, and no access to the application network or evidence credentials beyond a one-job upload capability.

### Relational database

PostgreSQL is the preferred shared-deployment database. SQLite is acceptable for a local single-user pilot but must not become the team system of record.

The database stores metadata and workflow history, not large evidence blobs.

### Evidence store

Local filesystem storage is adequate for development. A shared deployment should use organization-approved object or document storage with access control, retention, encryption, and immutable/versioned options where required.

Every stored artifact is addressed through database metadata and included in a digest manifest.

### Rules and templates

Workflow rules, reporting channels, message templates, and clauses are versioned data. They are not embedded as untraceable conditionals across route handlers.

### Integration adapters

All integrations are feature-gated:

- Microsoft Graph draft creation;
- internal notifications;
- approved commercial enrichment APIs;
- local OpenAI-compatible LLM endpoint or hosted provider;
- PDF, DOCX, XLSX, WARC, and WACZ exporters.

Core case processing must continue when every optional adapter is disabled.

## Deployment stages

### Local pilot

- localhost binding;
- single process for the web layer;
- local database and evidence directory;
- network collection disabled unless explicitly enabled;
- no SSO or shared access.

### Team pilot

- internal TLS endpoint;
- Entra ID or approved SSO;
- PostgreSQL;
- queue and workers;
- approved shared evidence store;
- audit logs and backups.

### Production

- separated browser worker network zone;
- high-availability stateful services as required;
- centralized observability without sensitive payloads;
- retention and legal-hold support;
- disaster recovery and access reviews.

## API boundaries

Initial resource families:

- `/api/v1/cases`
- `/api/v1/cases/{case_id}/snapshots`
- `/api/v1/cases/{case_id}/qualification`
- `/api/v1/cases/{case_id}/actions`
- `/api/v1/cases/{case_id}/drafts`
- `/api/v1/cases/{case_id}/exports`
- `/api/v1/campaigns`
- `/api/v1/admin/reporting-channels`
- `/api/v1/admin/templates`

Commands that have an external side effect must be visibly separate from preparation commands. The MVP does not expose an external-send command.
