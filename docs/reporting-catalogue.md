# Reporting-channel catalogue

## Purpose

The catalogue routes an operator to an official reporting or contact-discovery page. It never submits a form, decides that content is illegal, or treats a recommendation as proof that a channel accepted the case.

The application prepares bilingual factual summaries from the case and human qualification. Operators remain responsible for reviewing every copied field and for recording proof of any external submission.

## Current channels

The public catalogue was last extended on 2026-07-22 against official sources.
The operator interface presents operational channels in this order:

1. the sponsoring registrar, as the first direct operational contact;
2. search-engine and browser/user-protection services;
3. the registry operator responsible for the domain's TLD;
4. ICANN Contractual Compliance as an escalation after a direct report.

National authorities such as PHAROS remain contextual remedies outside this primary
technical escalation sequence.

| Channel | Purpose | Official source |
|---|---|---|
| ICANN Lookup | Find registrar information and published abuse contacts | `https://lookup.icann.org/en/faq` |
| Google Safe Browsing — phishing | Report phishing or social-engineering pages | `https://safebrowsing.google.com/` |
| Google Safe Browsing — malware | Report malware or unwanted-software pages | `https://safebrowsing.google.com/` |
| Microsoft Security Intelligence | Report unsafe URLs for Microsoft review | `https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site` |
| PHAROS | Report potentially illegal internet content in the official French scope | `https://www.service-public.gouv.fr/particuliers/vosdroits/R17674` |
| GMO Registry — .shop | Report abuse involving a `.shop` domain to the IANA-listed registry operator | `https://www.iana.org/domains/root/db/shop` |
| ICANN Contractual Compliance | Escalate an inadequately handled registrar or registry report | `https://www.icann.org/compliance/complaint` |

## Maintenance rule

Every channel record contains an action URL, source URL, last verification date, status,
priority group, optional TLD scope, required fields, and operator notes. A change must
update the verification date and tests. Unverified third-party directories must not be
added as authoritative sources. A registrar must never be inferred from DNS nameservers;
it is shown as unknown until registration data confirms it.

Links marked `review_needed` must remain visible as stale and must not be automatically suggested. Deprecated channels remain in history but are excluded from new workflows.

## Safety and privacy

- Opened pages receive no automatic POST and no case data from the toolkit.
- The operator copies only the prepared facts required by the selected channel.
- Evidence archives are not uploaded automatically.
- Recipient email values entered in the pilot are used in the local browser to construct a `mailto:` link and are not persisted.
- Legal or law-enforcement reporting remains a human decision.
