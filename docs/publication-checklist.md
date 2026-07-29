# Publication checklist

The repository is technically runnable but these owner-specific steps cannot be completed by code alone.

- [ ] Confirm the final public name and perform repository, package, domain, and trademark searches. A separate
      “W.H.Agent (White Hat Agent)” repository was found during development.
- [ ] Create the public GitHub repository and replace `<repository-url>` in the README.
- [ ] Add the repository owner's public identity to `MAINTAINERS.md` and a real `.github/CODEOWNERS` file.
- [ ] Enable branch protection: pull request required, CI required, conversation resolution required, force-push and
      deletion blocked.
- [ ] Enable GitHub Private vulnerability reporting and publish a private security contact or security.txt address.
- [ ] Enable secret scanning, push protection, dependency graph, Dependabot alerts, and code scanning where available.
- [ ] Decide whether DCO sign-off is enforced by a bot or manually.
- [ ] Confirm PyPI package-name ownership before publishing `white-hat-agent`.
- [ ] Add trusted publishing only after repository/environment identities exist; do not add a long-lived PyPI token.
- [ ] Build from a clean clone and test both wheel and source distribution.
- [ ] Create a signed `v0.1.0` tag and attach generated checksums and release notes.
- [ ] State clearly which adapters, if any, have received integration validation; do not imply the foundation alpha is
      an autonomous Internet scanner.
