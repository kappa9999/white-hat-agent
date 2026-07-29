# Release provenance and recovery

The repository is configured for GitHub immutable releases. Immutability begins only after publication, so the
release workflow verifies a complete draft before crossing that boundary. A version tag is accepted only when the
project version, latest changelog entry, tag object, GitHub-verified signature, target commit, generated schemas,
corpus manifest, and tag rules agree.

## Production release path

The `.github/workflows/release.yml` workflow runs only for a semantic version tag or a manual dispatch that targets
that exact tag. It performs these stages with job-scoped permissions:

1. **Gate:** reject a lightweight or invalidly signed tag, a version/changelog mismatch, dirty generated assets, an
   existing release, a commit other than the current protected `main` head, or a tag outside active
   creation/update/deletion/signature rules. Tag creation must be restricted to the maintainer role.
2. **Build twice:** create wheel and sdist in two isolated Ubuntu 24.04 jobs with pinned Python, uv, setuptools, and
   wheel versions, the tag commit time as `SOURCE_DATE_EPOCH`, and a dependency-resolution cutoff. Rewrite each sdist
   into the same extraction-safe, timestamp-normalized tarball.
3. **Compare:** require byte-for-byte equality for both independently built distributions; any drift fails closed.
4. **Assemble:** emit a six-file candidate: one wheel, one sdist, two subject-bound CycloneDX SBOMs describing their
   declared dependencies, `reproducibility.json`, and `SHA256SUMS` covering every other candidate file.
5. **Smoke:** install the exact candidate wheel and sdist into isolated environments, initialize a workspace, verify
   bundled assets and version output, and exercise the one-line installer against the candidate wheel.
6. **Attest:** in the `release-provenance` environment, use GitHub OIDC/Sigstore to attest every checksummed candidate
   file and `SHA256SUMS` itself, add subject-bound wheel and sdist SBOM attestations, and verify every subject through
   `gh attestation verify`.
7. **Publish:** in the `github-release` environment, create a draft, upload only the verifier's exact regular-file
   allowlist, persist its release ID, and compare every GitHub-computed asset name, uploaded state, byte size, and
   SHA-256 with the local candidate. Revalidate the signed tag and that exact draft immediately before publishing it
   by ID, then require `immutable: true` and reverify both the tag binding and remote assets.

No PyPI credential or upload action is present. PyPI publication must remain disabled until the `white-hat-agent`
namespace is controlled, a Trusted Publisher is bound to this repository and environment, and the protected
environment is explicitly approved.

## Maintainer procedure

1. Update `pyproject.toml`, the package version, and the top dated entry in `CHANGELOG.md` to the same stable version.
2. Regenerate and commit public schemas and the corpus manifest.
3. Merge through normal CI. Confirm `main` is clean and points to the intended commit. With an admin-scoped
   maintainer token, require `gh api repos/kappa9999/white-hat-agent/immutable-releases --jq .enabled` to print
   `true`, and verify the active tag ruleset has only the maintainer-role bypass. GitHub intentionally redacts
   `bypass_actors` from the least-privilege job token, so never grant the release job repository administration just
   to repeat this control-plane check.
4. Confirm the maintainer's SSH or GPG signing key is registered with GitHub, then create a **signed annotated** tag
   named `vX.Y.Z` at that commit. Never use a lightweight tag.
5. Push the tag once. Do not move or reuse it.
6. Watch the Release workflow through publication. Download the release into a clean directory and run:

   ```bash
   set -euo pipefail
   REPO=kappa9999/white-hat-agent
   TAG=vX.Y.Z
   TAG_OBJECT="$(gh api "repos/${REPO}/git/ref/tags/${TAG}" --jq .object.sha)"
   COMMIT="$(gh api "repos/${REPO}/git/tags/${TAG_OBJECT}" --jq .object.sha)"
   attestation_policy=(
     --repo "$REPO"
     --signer-workflow "$REPO/.github/workflows/release.yml"
     --source-ref "refs/tags/${TAG}"
     --source-digest "$COMMIT"
     --deny-self-hosted-runners
   )
   sha256sum --check SHA256SUMS
   while read -r _ artifact; do
     gh attestation verify "$artifact" "${attestation_policy[@]}"
   done < SHA256SUMS
   gh attestation verify SHA256SUMS "${attestation_policy[@]}"
   ```

7. Install the released artifact in a disposable environment before announcing availability.

## Failure and rollback

- **Before publication:** a failed draft is still mutable but is not public. Preserve its workflow evidence and leave
  the failed tag in place; fix the defect, increment the patch version, and create a new signed tag. Do not clobber
  draft assets, force-update the tag, or silently reuse the version.
- **Bad GitHub release:** mark the release as affected and publish a fixed patch release. Do not replace assets under
  the original version. If an asset was malicious or exposed a secret, remove access only as incident containment and
  preserve an internal evidence copy and audit timeline.
- **PyPI, when enabled:** yank a functionally broken version; do not delete it merely to reuse the version. Revoke the
  Trusted Publisher binding if its identity boundary may be compromised.
- **Compromised tag or signing key:** stop release jobs, disable the release environments, revoke/remove the signing
  key, preserve workflow/tag/attestation evidence, publish a security notice from a newly trusted identity, rotate any
  affected credentials, and issue a new version. Never bless a moved tag.
- **Compromised GitHub Actions dependency:** disable the workflow, identify every release containing the affected
  action commit, verify artifact subjects independently, rotate pinned action SHAs only after review, and republish
  under a new version if integrity cannot be proven.

The GitHub Release is a distribution boundary, not the only recovery copy. Source tags, workflow logs, uploaded
candidate artifacts, signed attestations, and release assets should agree on the same commit and SHA-256 subjects.
