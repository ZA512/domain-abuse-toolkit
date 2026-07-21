# Security and evidence model

## Core assumption

The target URL, DNS answers, redirects, certificates, headers, HTML, JavaScript, images, documents, and extracted text are controlled by an adversary.

## Network controls

Before each connection:

1. Parse and normalize the URL without resolving it.
2. Allow only `http` and `https` for web collection.
3. Reject credentials, ambiguous hosts, invalid ports, and malformed IDNs.
4. Resolve all A and AAAA answers.
5. Reject the target if any selected destination is private, loopback, link-local, multicast, reserved, or unspecified.
6. Connect using the validated destination while preserving the intended host/SNI.
7. Apply the same process to every redirect.
8. Re-resolve according to a bounded policy to detect rebinding.

Shared deployment must additionally use egress firewall rules that prevent access to internal, link-local, metadata-service, and management networks even if application checks fail.

## Collection limits

- bounded connect/read/total timeout;
- bounded redirect count;
- bounded response and decompressed-body size;
- bounded DNS answers and certificate-chain depth;
- explicit content-type policy;
- no automatic download execution or file opening;
- sanitized log fields;
- per-target and global rate limits.

### Current passive DNS implementation

The local pilot keeps network collection disabled unless started with the dedicated opt-in launcher. A separate case-page confirmation starts a bounded job for `A`, `AAAA`, `CNAME`, `MX`, `NS`, and `TXT` records. Per-query timeout, total query lifetime, record count, worker concurrency, one-running-job-per-case, and the global pending queue are bounded. Any private, loopback, link-local, reserved, multicast, or otherwise non-global address makes the snapshot fail and blocks its use by later connection-based collectors. Error messages do not repeat the prohibited address.

Successful DNS response messages are preserved as `application/dns-message` originals below `10_snapshots/<snapshot-id>/dns/`. The normalized snapshot and its failure details are stored as an immutable event. DNS collection does not imply that the website was opened or that its content was reviewed.

### Current HTTP/TLS implementation

After the DNS safety gate succeeds, the local worker resolves the current host again, rejects the entire answer set if any address is non-global, selects one validated address deterministically, and connects directly to it while preserving the intended HTTP `Host` and TLS SNI. Every redirect is normalized, length-limited, loop-checked, freshly resolved and revalidated. Redirects to credentials, prohibited schemes, non-standard ports or non-public networks stop before a connection. HTTPS-to-HTTP downgrade is retained as a structured warning.

The request sends no cookie, authorization value or browser state, asks for identity encoding and a bounded byte range, and uses `Connection: close`. Only textual, JSON or XML response bodies are retained, up to the configured limit; attachment and other content types are not downloaded. Human-facing observations use an explicit response-header allowlist that excludes `Set-Cookie`. The TLS handshake uses TLS 1.2 or later for evidence capture, stores the leaf DER certificate, and records fingerprint, subject, issuer, SAN, validity, protocol and cipher. Certificate trust validation is deliberately reported as not performed; the collected certificate is evidence, not a trust decision.

### Current RDAP implementation

The collector derives the registrable domain from the normalized case target, downloads the official IANA DNS bootstrap registry over certificate-validated HTTPS, and selects the HTTPS service published for the target TLD. The bootstrap and authoritative domain response are size-bounded, parsed as JSON only, cached for a bounded period, and preserved as immutable evidence. Every bootstrap or registry address and every redirect must resolve exclusively to public IP addresses; HTTPS certificate validation remains enabled for these trusted service endpoints.

Only operational registration fields are normalized for the interface: domain identifiers, statuses, events, nameservers, DNSSEC state, registrar identifiers/name, and an abuse email explicitly published by an entity with the `abuse` role. Registrant contact data is not normalized or displayed. The raw authoritative response may nevertheless contain personal data published by a registry, so case access, retention, and evidence exports must remain restricted and proportionate.

## Browser isolation

The implemented pilot capture does not revisit the target. It sends only the already bounded HTML evidence to a pinned local Playwright image running in an ephemeral Docker container. The container has no network interface, a read-only root filesystem, a bounded temporary filesystem, dropped Linux capabilities, `no-new-privileges`, and explicit CPU, memory, process, file, screenshot-dimension, output-size, and wall-clock limits. Chromium uses a clean context with JavaScript, service workers, downloads, permissions, and every browser request disabled. The container returns one PNG and is removed after the job.

This PNG is a derived offline rendering linked to its original HTTP-body artifact. It can establish how the bounded static HTML rendered under the recorded policy, but it is not represented as a live full-fidelity screenshot. External styles, images, fonts, frames, and dynamic application content are intentionally absent.

A future live browser worker must not run inside the web application process. It requires:

- ephemeral container and browser profile;
- read-only base image;
- non-root user;
- private-network deny rules;
- no cloud instance metadata access;
- no host mounts or reusable download directory;
- denied browser permissions and disabled downloads;
- resource, time, and navigation limits;
- one-job credentials for artifact upload only;
- destruction after the job.

Screenshots are useful evidence but are not proof of every network transaction. Preserve technical observations and raw artifacts alongside them.

## Evidence lifecycle

### Original

Bytes captured directly from an approved source: raw bounded HTTP response, RDAP JSON, certificate, screenshot, or submitted acknowledgement.

### Derived

Human-readable conversion, OCR, redaction, annotation, PDF rendering, comparison image, or summary. A derived artifact points to every source artifact and records the transformation version.

### Manifest

Every export includes the exact JSON manifest with artifact IDs, relative paths, byte sizes, SHA-256 digests, timestamps, media types, origins, and derivations. The local pilot produces a deterministic ZIP from registered artifacts only and includes a standalone verifier that recalculates every digest, enforces size limits, rejects unsafe paths, duplicate members, symbolic links, and unregistered files.

### Timestamping

Application UTC timestamps and audit records are sufficient for the MVP. If the legal requirement demands stronger assurance, add an approved trusted timestamp or signed WACZ mechanism without changing original evidence bytes.

## Data minimization

- Do not retain routine cookies, authorization headers, or personal browser state.
- Redact or exclude `Set-Cookie` and other sensitive headers from human-facing reports while preserving only an approved original where necessary.
- Do not send full evidence to optional enrichment or LLM services.
- Treat victim data as a separate restricted record, not ordinary case notes.
- Make exports configurable so recipients receive only the evidence required for their role.

## LLM controls

Site content is data, never an instruction. The LLM receives a bounded, sanitized fact object and explicit schema. It has no tool access and cannot transition state, choose a recipient, create an external draft, or submit anything.

The application records provider, model, prompt/template version, input artifact references, output, validator result, and human disposition. A deterministic template remains available when the LLM is disabled or fails.

## Public repository controls

- `private/`, `evidence/`, `case-data/`, exports, captures, email files, archives, databases, logs, secrets, and environment files are ignored.
- Tests use reserved example domains and documentation IP ranges.
- CI should include secret scanning and a denylist check for organization-specific terms before public publication.
- A private deployment repository may consume this public package, but private configuration must never flow back into the public source tree.
