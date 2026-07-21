# ADR 0001 - Docker Compose runtime and browser isolation

- Status: accepted
- Date: 2026-07-21

## Context

The local pilot currently runs the web application through WSL and starts a short-lived, networkless Playwright container for offline HTML rendering. That model is safe but installation depends on both WSL and Docker, and the offline renderer cannot reproduce dynamic pages or external images and fonts.

A full remote desktop image such as LinuxServer Firefox would provide a familiar browser, but it would also expose a reusable interactive browser environment to hostile pages. It does not provide the job-level network policy, clean profiles, bounded artifacts, or deterministic automation needed by an evidence collector.

## Decision

The supported local runtime will progressively move to Docker Compose. The first delivered profile contains the web application behind a fixed reverse proxy and keeps every side-effecting feature disabled. Only the proxy binds to `127.0.0.1`. The application runs as a non-root user with a read-only root filesystem, drops Linux capabilities, uses an internal Docker network without outbound connectivity, and stores cases in a named volume. The proxy has no dynamic forwarding target and cannot expose arbitrary destinations.

The web application never receives the Docker socket.

Live capture will be added as separate services, not by installing a general-purpose desktop browser in the web container:

1. the web application records an operator-authorized job;
2. a worker receives a bounded job description and a one-job artifact credential;
3. an ephemeral Playwright browser uses a fresh context, denied permissions and disabled downloads;
4. all browser traffic crosses a controlled egress gateway that blocks private, loopback, link-local, metadata and management destinations after every resolution and redirect;
5. the worker uploads only bounded artifacts and is destroyed.

The current deterministic offline screenshot remains available because it is safer and more reproducible. A later live mode will be clearly labelled as a separate evidence type. JavaScript-disabled live capture should precede any JavaScript-enabled mode.

## Consequences

- `START_TOOLKIT_DOCKER.cmd` gives a one-click, WSL-free safe-mode launch.
- A minimal fixed reverse proxy bridges the Windows loopback listener to the isolated application network.
- Existing WSL launchers remain available during the migration, including the explicitly authorized passive collector and offline renderer.
- The Docker safe profile cannot collect from the Internet and cannot create screenshots yet.
- Evidence is kept outside the source tree in the `domain-abuse-toolkit-evidence` named volume.
- A controlled egress gateway and an explicit job boundary are prerequisites for live browsing.
- Authentication, authorization, retention and an approved shared evidence store remain prerequisites for a team deployment.
