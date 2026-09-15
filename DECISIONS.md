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

## Typed CRD models + reference server testing (2026-09-15)

- Added typed contexts for all six CRD hooks (`CrdHookContext`), CRD prefetch
  keys (`CrdPrefetch`), `fhirServer`/`fhirAuthorization` on requests, and on
  responses: typed card `source`/`topic`, `systemActions`, discovery
  `prefetch` templates, and `CoverageInformation` parsing.
- FHIR resources are kept as Jackson `JsonNode`s instead of adding HAPI FHIR,
  to keep the library light. HAPI could be an optional adapter module later.
- Tested against the HL7 Da Vinci CRD reference implementation
  (`HL7-DaVinci/CRD`, built from `master` on 2026-09-15). Differences found
  between it and the 2.2.1 spec, which the client now handles:
  - It uses its own prefetch keys, not CRD's `patient`/`coverage`.
  - It returns coverage information inside card suggestions, not
    `systemActions`.
  - It uses the older `identifier` sub-extension instead of
    `coverage-assertion-id`, and adds `questionnaire`.
- The live test only checks that the right rule matched and that the response
  parses. The rule's decision depends on the server's CQL (for the synthetic
  patient it returned "No Prior Authorization required").

## Auth and mutual TLS (2026-09-15)

The user chose each of these when asked:

- **Mutual TLS is a transport setting, not an `authType`.** `MUTUAL_TLS` was
  removed from the enum and replaced by an optional `mtlsCredentialRef`, so it
  can be combined with any app-layer auth. CDS Hooks describes mTLS as used
  "alongside" JWTs, and a payer may require mTLS plus OAuth. This changes the
  schema locked in the 2026-09-12 scoping session. Nothing was published yet,
  so there was no compatibility cost.
- **New auth types.** `CDS_HOOKS_JWT` is the CDS Hooks 2.0 client JWT.
  `OAUTH2_PRIVATE_KEY_JWT` is the RFC 7523 client assertion used by SMART
  Backend Services.
- **New record fields.** `keyId` (`kid`), `jwksUrl` (`jku`), and `tenant`
  (the optional CDS Hooks claim, sent only when set).
- **JWT signing uses Nimbus JOSE+JWT** (10.9.1, no required transitive
  dependencies) rather than hand-written JWS code.
- **Algorithms are RS384 (RSA 2048+) and ES384 (EC P-384) only**, taken from
  the key, which are the algorithms CDS Hooks and SMART recommend.
- **Private keys are PKCS#8 PEM behind `credentialRef`.** The mTLS credential
  is a PEM bundle (certificate chain plus key). No secrets are stored on the
  record.
- **JWKS publishing is a helper (`Jwks`), not a hosted endpoint**, to stay
  library-first.
- **TLS 1.2 is the minimum** on clients the SDK builds, following the HRex
  guidance CRD points to.
- **Tests generate throwaway keys and certificates at runtime** (JDK
  `KeyPairGenerator` and `keytool`), so no private keys are committed.

## Not yet done

- No publishing config (Maven Central / GitHub
  Packages).
- No real payer has been contacted. The client has been tested against the
  HL7 Da Vinci CRD reference implementation running locally in Docker, but
  not against any payer's sandbox.
- Typed contexts don't validate against full FHIR profiles, and FHIR
  resources are untyped `JsonNode`s.
