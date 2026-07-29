# 0001: Working project name

- Status: provisional
- Date: 2026-07-29

## Decision

Use **White Hat Agent Core** as the working product name and `white-hat-agent` as the Python distribution name during
foundation development.

## Context

“White Hat Agent” communicates the intended public project, but a June 2026 GitHub project named “W.H.Agent (White
Hat Agent)” exists in the adjacent agent-sandboxing space. No claim of name or trademark clearance is made.

## Consequence

The code avoids hard-coding a nonexistent repository owner or URL. The owner must complete a current naming,
repository, package, domain, and trademark check before publication. Renaming remains mechanical because Python uses
the distinct `white_hat_agent` namespace and public protocol objects carry schema versions rather than brand names.
