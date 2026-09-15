# Scaffolding Decisions (2026-09-13)

The architecture itself was locked in the 2026-09-12 scoping session (see the
`fhir-crd-payer-router` memory capsule). This file records the choices made
to actually generate a buildable repo, since those were left open. All of
them are cheap to change — nothing below is load-bearing for the locked
architecture.

| Open question | Default chosen | Rationale / how to change it |
| --- | --- | --- |
| Repo/project name | `fhir-crd-router` | Matches the capsule's own working name. Rename the folder + `<name>` in root `pom.xml` if you want something else. |
| Java package/group ID | `io.github.dflippo` | Neutral personal-OSS convention (matches a GitHub-hosted repo). Swap for a personal domain if you have one you'd rather use — it's a find/replace across `pom.xml` files and Java package declarations. |
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

## Not yet done

- Not pushed to GitHub, and no publishing config (Maven Central / GitHub
  Packages).
- No real payer has been contacted. `examples-quickstart` talks to an
  in-process mock CDS Hooks server, not a real sandbox.
- `MUTUAL_TLS` still depends on the caller building an `HttpClient` with the
  right `SSLContext`.
- `clientId:clientSecret` is still packed into a single `credentialRef`
  secret (see `OAuth2TokenClient` javadoc). Decide whether the schema should
  get an explicit `clientId` field.
- The request model is generic maps. There are no typed CRD
  `context`/`prefetch` shapes for `order-sign`, `order-select`, or
  `appointment-book` yet.
