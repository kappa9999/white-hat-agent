# Security policy

## Supported versions

Before the first stable release, only the latest commit on `main` is supported. After stable releases begin, this
table will name supported release lines.

## Reporting a vulnerability in White Hat Agent Core

Do not open a public issue containing a vulnerability, credential, private program rule, or undisclosed finding.
Use GitHub [Private vulnerability reporting](https://github.com/kappa9999/white-hat-agent/security/advisories/new).
The sole maintainer will acknowledge a report, coordinate validation and remediation, and publish an advisory when
appropriate.

If that channel is unavailable, withhold technical details and open a detail-free issue asking the maintainer to
restore the private reporting channel.

Include:

- affected version or commit;
- exact component and configuration;
- minimal reproduction using synthetic data;
- impact and preconditions;
- evidence and relevant digests; and
- suggested remediation, if known.

## Scope of this policy

This channel covers vulnerabilities in the core, its official schemas, built-in corpus, release artifacts, and
official adapters. Vulnerabilities discovered *using* White Hat Agent Core should follow the affected program's
captured disclosure policy and must not be posted here merely because this project helped find them.
