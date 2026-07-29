# Public-advisory code-generator differential

This is a **local, public-advisory differential performed on 2026-07-29**. It validates two already published
`swagger-typescript-api` behaviors with exact vulnerable and fixed package artifacts. It is not a new vulnerability
claim.

The generated TypeScript was treated only as text. It was **never compiled, imported, evaluated, or executed**. The
external-reference check used only two short-lived servers bound to `127.0.0.1` on different ephemeral ports. Do not
adapt this example to scan a remote target, contact production infrastructure, or execute injected generated output.

The reusable method is captured in the
[untrusted code-generator differential playbook](../../../corpus/playbooks/supply-chain/untrusted-code-generator-differential/playbook.yaml).

## Public provenance

- [GHSA-w284-33mx-6g9v](https://github.com/advisories/GHSA-w284-33mx-6g9v) /
  CVE-2026-54666: "Code injection via unescaped OpenAPI path strings in generated method bodies; per-method-call RCE."
- [GHSA-x36r-4347-pm5x](https://github.com/advisories/GHSA-x36r-4347-pm5x) /
  CVE-2026-54663: "Server-Side Request Forgery via spec `$ref`; generator makes attacker-directed HTTP requests during
  code generation when run against an attacker-controlled OpenAPI spec."
- Upstream fix: [PR #1779, `Security/fixing vulnerabilities`](https://github.com/acacode/swagger-typescript-api/pull/1779),
  merged as [`306d59acb8ffbb00f953f807b97234b21f51d9de`](https://github.com/acacode/swagger-typescript-api/commit/306d59acb8ffbb00f953f807b97234b21f51d9de).
- Relevant upstream commits: generated-path fix
  [`3240c387fbb02c44c2a5eec1e825dc023a5ee3fe`](https://github.com/acacode/swagger-typescript-api/commit/3240c387fbb02c44c2a5eec1e825dc023a5ee3fe),
  external-reference fix
  [`8fdcf7f64b394a4e7c95d46933b854c1fa97d70e`](https://github.com/acacode/swagger-typescript-api/commit/8fdcf7f64b394a4e7c95d46933b854c1fa97d70e),
  and follow-up hardening
  [`495f2cd8b2c5102cfb311b81db4c07d1024896dd`](https://github.com/acacode/swagger-typescript-api/commit/495f2cd8b2c5102cfb311b81db4c07d1024896dd).

The quoted titles above preserve the public advisory wording. The test design and this write-up are original
documentation of a local reproduction.

## Exact identities

The evidence window was `2026-07-29T15:29:11Z` through `2026-07-29T15:37:41Z` on Linux with Node `v26.5.0` and npm
`12.0.1`.

| Role | Package | Annotated tag object | Peeled commit / npm `gitHead` | npm tarball SHA-256 |
|---|---|---|---|---|
| vulnerable | [`13.12.1`](https://github.com/acacode/swagger-typescript-api/releases/tag/v13.12.1) | `11fd112e3045205372eebd35931ba275bfe8a986` | `ee5034b1fcce29d1962923fa689fc8570cfdf075` | `cfe3b4a4cc5003da978942ae7df5d11744f4864cd09f8b33489361e89b4648e7` |
| fixed | [`13.12.2`](https://github.com/acacode/swagger-typescript-api/releases/tag/v13.12.2) | `4643bae4022077cd2b242bf34fc3aaf1f475ce35` | `cc3e4d1598dfd990b8d862b88cd64ae1ca7653e3` | `817e64c346b5a8e85e2118caf410128d762fc754ae865cab3a8d88b0e8a6eb9b` |

The npm artifacts came from these immutable version URLs:

- `https://registry.npmjs.org/swagger-typescript-api/-/swagger-typescript-api-13.12.1.tgz`
- `https://registry.npmjs.org/swagger-typescript-api/-/swagger-typescript-api-13.12.2.tgz`

## Inert generated-text differential

[`payload-spec.json`](./payload-spec.json) contains the side-effect-free path marker
`/api/${"STA_PATH_SENTINEL_54666"}/items`. The marker is never invoked. [`control-spec.json`](./control-spec.json) uses
the legitimate declared path parameter `/api/users/{id}/items`. Both fixtures use the reserved, non-routable
`example.invalid` domain.

### Observed matrix

| Package | Inert payload line in generated `Api.ts` | Benign control line |
|---|---|---|
| `13.12.1` | ``path: `/api/${"STA_PATH_SENTINEL_54666"}/items`,`` | ``path: `/api/users/${id}/items`,`` |
| `13.12.2` | ``path: `/api/\${"STA_PATH_SENTINEL_54666"}/items`,`` | ``path: `/api/users/${id}/items`,`` |

The source diff predicted the extra backslash in the fixed payload output and preservation of the intended control
interpolation. The four cells matched that prediction. `modular: true` was also checked independently and showed the
same behavioral matrix.

### Hash ledger

The published lab's payload fixture is byte-identical to the checked-in payload. Its historical control used the same
declared path-parameter semantics but different serialization/content, so its historical hash is retained separately
instead of being attributed to this generalized control file.

| Artifact | SHA-256 |
|---|---|
| historical and checked-in payload fixture | `a05c559afff1acb4a6639413014c05bac8f62c960e2a8e525f5bbb8f25edcea0` |
| historical control fixture | `77cabd2999a9cbeb8cdfaccdbcad00fe8fa09acae0dca46d6493492e2234cd6d` |
| checked-in generalized control fixture | `b93cc801110abda75adc931cf9a961430d42b82cbec7abadd0c25a3ee27149c6` |
| historical and current `13.12.1` payload output | `b7ba33c74067c45cad28faa5c7bc11cce982a1ac9b52d8db6c0ca3d569c46f87` |
| historical and current `13.12.2` payload output | `5b331d833d89bf68e2dd15ce33eaf41787f366d3f6bf125e718e790010f95fb0` |
| historical control output, both versions | `8b78ab34472ff0ffe65f0279c89f279109c869214b668d62dbfabce74925ae67` |
| checked-in generalized control output, both versions | `101a03f4af01c332a24a0e767a246c878a402b15f4a0f7f4231e42e3942dc82e` |

### Safe local reproduction

Run this from the repository root in a disposable local environment. These commands generate files and inspect text;
they do not run generated files.

```bash
WHA_CODEGEN_REPO="$(pwd -P)"
WHA_CODEGEN_LAB="$(mktemp -d)"
mkdir -p "$WHA_CODEGEN_LAB/tarballs"

npm pack swagger-typescript-api@13.12.1 --pack-destination "$WHA_CODEGEN_LAB/tarballs"
npm pack swagger-typescript-api@13.12.2 --pack-destination "$WHA_CODEGEN_LAB/tarballs"
sha256sum "$WHA_CODEGEN_LAB"/tarballs/*.tgz

for version in 13.12.1 13.12.2; do
  mkdir -p "$WHA_CODEGEN_LAB/v$version"
  npm install --prefix "$WHA_CODEGEN_LAB/v$version" \
    --ignore-scripts --no-audit --no-fund --package-lock=false \
    "swagger-typescript-api@$version"

  for fixture in payload control; do
    output="$WHA_CODEGEN_LAB/v$version/out-$fixture"
    mkdir -p "$output"
    (
      cd "$WHA_CODEGEN_LAB/v$version"
      timeout 60s node --input-type=module -e \
        'import { generateApi } from "swagger-typescript-api";
         const [input, output] = process.argv.slice(1);
         await generateApi({name: "Api.ts", output, input, httpClientType: "fetch", silent: true});' \
        "$WHA_CODEGEN_REPO/examples/research/code-generator-differential/$fixture-spec.json" \
        "$output"
    )
  done
done

rg -n -F 'STA_PATH_SENTINEL_54666' "$WHA_CODEGEN_LAB"/v*/out-payload/Api.ts
rg -n -F 'path: `/api/users/' "$WHA_CODEGEN_LAB"/v*/out-control/Api.ts
sha256sum "$WHA_CODEGEN_LAB"/v*/out-*/Api.ts
```

Stop after the text and hash checks. Do not send any generated file to `node`, a TypeScript runner, a compiler, a
bundler, a test runner, or an application. After preserving the bounded evidence, remove only the exact disposable
directory printed in `WHA_CODEGEN_LAB`.

## Loopback-only external-reference differential

The second local test exercised the behavior documented by GHSA-x36r-4347-pm5x. It used one ephemeral loopback server
for the specification and a different ephemeral loopback server as a request counter. The control response schema was
inline; the payload response schema contained one `$ref` to a unique path on the counter. No listener bound beyond
`127.0.0.1`, and no public, private-network, link-local, or production address was used.

### Observed loopback matrix

| Package | Control counter hits | Payload counter hits |
|---|---:|---:|
| `13.12.1` | 0 | 1 |
| `13.12.2` | 0 | 0 |

The structured result log SHA-256 was
`4aa2d6d00e46ff3f5c2ff1f11b7939e37cd1d12217e1b4d60a052f17c5a96e56`.

Reproduction pseudocode, intentionally constrained to loopback:

```text
for each exact package version:
  bind counter_server to 127.0.0.1 on an OS-assigned port
  bind spec_server to 127.0.0.1 on a different OS-assigned port
  assert both bound addresses are exactly 127.0.0.1

  for control, serve a spec with an inline response schema
  for payload, serve the same spec with one $ref to:
    http://127.0.0.1:<counter_port>/WHA_LOOPBACK_ONLY_COUNTER/schema.json

  run generateApi({url: spec_server_url, ...same_options}) with a 60-second timeout
  record only counter hit count, unique path, package identity, and timestamps

  finally close both servers and verify both ports are closed
```

This is a request-counter differential, not a network scan. Never substitute another host for `127.0.0.1`.

## Upstream regression status

At the fixed upstream source identity, this focused command completed with **3 files and 15 tests passed**:

```bash
npx vitest run \
  tests/route-path-injection.test.ts \
  tests/escape-js-template-literal-with-path-params.test.ts \
  tests/resolved-swagger-schema-ssrf.test.ts \
  --reporter=verbose
```

That upstream result complements the local package differential; it does not replace the exact tarball, fixture,
generated-output, and loopback evidence above.

## Limitations

- This reproduces public advisories on one Linux/Node/npm environment. It does not establish behavior for every
  platform, runtime, generator option, or dependency graph.
- Because generated code was never executed, the local sentinel evidence establishes emitted syntax treatment, not an
  independent re-demonstration of advisory impact.
- The local request-counter matrix covered one direct cross-origin IPv4 loopback `$ref`. It does not independently
  validate every redirect, DNS, IPv6, same-origin, or authorization-header case.
- `modular: true` matched the observed sentinel behavior, but the hash ledger above records the default non-modular
  output only.
- A successful fixed differential validates these exact artifacts and fixtures. It is not proof that adjacent input
  channels or later versions are free of vulnerabilities.
