# Scaffolding Decisions (2026-09-13, confirmed 2026-09-15)

The architecture itself was locked in the 2026-09-12 scoping session (see the
`fhir-crd-payer-router` memory capsule). This file records the choices made
to actually generate a buildable repo, since those were left open. The user
confirmed all of them on 2026-09-15, with one change: the group ID and
package became `io.github.dflippojr` to match the GitHub account, which
Maven Central requires for `io.github.*` namespaces.

| Open question | Default chosen | Rationale / how to change it |
| --- | --- | --- |
| Repo/project name | `fhir-crd-router` | Matches the capsule's own working name. Rename the folder + `<name>` in root `pom.xml` if you want something else. |
| Java package/group ID | `io.github.dflippojr` | Matches the `dflippojr` GitHub account, which Maven Central requires for an `io.github.*` namespace. |
| Minimum Java version | 17 (LTS) | Modern enough for records/sealed types, old enough to be uncontroversial as a library baseline. This machine currently only has JDK 8 installed — you'll need a JDK 17+ (e.g. via Temurin) to actually build this. |
| Build tool | Maven | Slightly more conventional than Gradle for publishing a small library to Maven Central as a solo maintainer; also not currently installed on this machine (only `git` and JDK 8 were found) — install Maven 3.9+ before building. |
| Connection record persistence (v1) | Flat YAML file, behind a `ConnectionStore` interface | Mirrors the same pluggable-adapter pattern already locked for credentials. `FileBasedConnectionStore` is the default impl; swapping in a DB-backed store later is just a new implementation of the interface. |

## Follow-up session (2026-09-15)

- Build verified: `./mvnw verify` passes (17 tests) on JDK 21, and the
  quickstart runs end-to-end.
- Switched `maven.compiler.source/target` to `maven.compiler.release=17` so
  building on a newer JDK can't silently use post-17 APIs.
- Added the Maven wrapper (Maven 3.9.9) and a GitHub Actions CI workflow
  (JDK 17 + 21 matrix). The workflow is untested until the repo is pushed.
- `client-sdk`: in-memory OAuth2 token caching (honors `expires_in` with a
  30s skew) and a single retry with a fresh token on 401. Covered by new tests.
- Mock server and tests now use `order-sign`, a hook CRD actually defines,
  instead of `patient-view`.
- Fixed the quickstart run command (`-am exec:java` failed in the upstream
  modules).

## Schema change: explicit `clientId` (2026-09-15)

`ConnectionRecord` gained a `clientId` field, required when
`authType = OAUTH2_CLIENT_CREDENTIALS`. `credentialRef` now resolves to the
client secret alone. This matches RFC 6749, where the client ID is a public
identifier and only the secret is a credential. The token request uses
`client_secret_basic`, which servers are required to support.

Not built yet: CDS Hooks' own spec has CDS clients authenticate by sending a
JWT signed with the client's private key (the service verifies it against the
client's JWKS), and SMART Backend Services uses `private_key_jwt`. If real
payers expect either, that would be a new `authType` rather than a change to
this one.

## Not yet done

- No publishing config (Maven Central / GitHub
  Packages).
- No real payer has been contacted. `examples-quickstart` talks to an
  in-process mock CDS Hooks server, not a real sandbox.
- `MUTUAL_TLS` still depends on the caller building an `HttpClient` with the
  right `SSLContext`.
- The request model is generic maps. There are no typed CRD
  `context`/`prefetch` shapes for `order-sign`, `order-select`, or
  `appointment-book` yet.
