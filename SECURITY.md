# Security policy

## Reporting a vulnerability

Do not open a public GitHub issue for a vulnerability that could expose evidence, credentials, internal infrastructure, or personal data. Contact the project maintainers through the organization's approved private security channel.

## Sensitive data policy

Never commit:

- real case evidence or captures;
- customer or victim information;
- mailbox contents or exported messages;
- API keys, tokens, certificates, or `.env` files;
- confidential procedures, brand reference packs, or legal documents;
- production URLs, internal hostnames, or infrastructure details.

Use synthetic examples in tests and documentation. The reserved domains `example.com`, `example.net`, and `example.org`, and documentation IP ranges such as `192.0.2.0/24`, must be used for examples.

## Threat boundary

Every submitted URL and every byte returned by a target is hostile input. Collectors must defend against SSRF, DNS rebinding, redirect-to-private-network attacks, oversized responses, decompression bombs, hostile markup, prompt injection, and unsafe browser behavior.

Local HTML state changes require an unguessable per-process form token. JSON APIs reject state-changing requests carrying a cross-site browser origin.

See [docs/security-and-evidence.md](docs/security-and-evidence.md) for the detailed control model.
