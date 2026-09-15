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

## Not yet done

- Nothing has been published or built — this machine can't compile Java 17
  without a newer JDK installed, so none of this has been verified to
  actually compile. Install a JDK 17+ and Maven, then run `mvn -q -pl
  directory-core,client-sdk,credential-store-encrypted-local,examples-quickstart
  -am test` (or just `mvn test` from the root) to check.
- No CI, no publishing config (Maven Central / GitHub Packages), no real
  payer has been contacted — `examples-quickstart` talks to an in-process
  mock CDS Hooks server, not a real sandbox.
- OAuth2 client-credentials token fetch in `client-sdk` is a minimal
  implementation — no retry/backoff, no token caching yet.
