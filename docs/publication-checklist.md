# Publication checklist

The public repository is live. Checked items were verified during the initial publication on 2026-07-29; remaining
items require a naming or release decision from the owner.

- [ ] Confirm the final public name and perform repository, package, domain, and trademark searches. A separate
      “W.H.Agent (White Hat Agent)” repository was found during development.
- [x] Create the public GitHub repository and publish the canonical clone URL.
- [x] Add the repository owner's public identity to `MAINTAINERS.md` and `.github/CODEOWNERS`.
- [x] Enable branch protection: pull request required, CI required, conversation resolution required, force-push and
      deletion blocked.
- [x] Enable GitHub Private vulnerability reporting and link it from `SECURITY.md`.
- [x] Enable secret scanning, push protection, dependency graph, Dependabot alerts, and CodeQL default setup.
- [x] Enforce DCO sign-off through maintainer review during the foundation phase.
- [ ] Confirm PyPI package-name ownership before publishing `white-hat-agent`.
- [ ] Add trusted publishing only after repository/environment identities exist; do not add a long-lived PyPI token.
- [x] Build from a clean clone and test both wheel and source distribution.
- [ ] Create a signed `v0.1.0` tag and attach generated checksums and release notes.
- [x] State clearly which adapters, if any, have received integration validation; do not imply the foundation alpha is
      an autonomous Internet scanner.
