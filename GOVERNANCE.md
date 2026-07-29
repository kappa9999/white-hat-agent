# Governance

## Current model

White Hat Agent Core uses a **single-maintainer model** while the project is early. The repository owner is the sole
maintainer and final decision maker. This keeps corpus quality, protocol stability, release provenance, and security
response unambiguous while the core interfaces are established.

## Contributions

Anyone may open an issue or pull request. A contribution can include code, an adapter contract, a corpus playbook,
translation, test fixture, taxonomy mapping, documentation, or a reproducible negative result. Contributor status
means the contribution was accepted; it grants no repository permissions.

All contributions use the Apache-2.0 terms in [LICENSE](LICENSE). Commits must carry a Developer Certificate of Origin
sign-off (`Signed-off-by: Name <email>`), confirming the contributor has the right to submit the work.

## Decisions

The maintainer evaluates changes using these priorities, in order:

1. reproducibility and evidence integrity;
2. exact scope, target, task, and artifact identity;
3. generality across models, tools, platforms, and cyber domains;
4. composability through typed inputs, outputs, and capabilities;
5. usability for people who are not AI-native; and
6. implementation and maintenance cost.

Substantial protocol, schema, governance, licensing, or trust-boundary changes require a short decision record under
`docs/decisions/`. The maintainer may reject a contribution without rejecting the underlying knowledge; for example,
a valuable technique can be returned for missing provenance, reproducibility, or a bounded fixture.

## Future maintainers

The repository owner may appoint maintainers after sustained, high-quality contributions. Appointments are recorded
in this file and `MAINTAINERS.md`; repository permissions are never inferred from contribution count. A future
multi-maintainer policy should define review quorum, release keys, inactive-maintainer handling, and removal.
