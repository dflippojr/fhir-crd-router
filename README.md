# FHIR CRD Router

A small, personal, open-source Java library that resolves `payerId ->
connection record` for medical insurance payers' FHIR CRD (CDS Hooks)
endpoints, plus an optional client SDK that uses a resolved record to make
the actual CDS Hooks call.

This is **discovery/directory only**: the router never touches patient data.
See [DECISIONS.md](./DECISIONS.md) for the design and scaffolding choices
(why discovery-only, why library-first, why the credential store is
pluggable, how auth and mutual TLS are modeled).

## Modules

- **`directory-core`**: the `ConnectionRecord` model, the `ConnectionStore`
  interface with a default flat-YAML-file implementation
  (`FileBasedConnectionStore`), the `CredentialProvider` interface, and
  `PayerRouter` (the `payerId -> ConnectionRecord` resolver). A record carries
  the payer's base URL, environment, `authType` and the non-secret auth
  settings (`tokenEndpoint`, `clientId`, `keyId`, `jwksUrl`, `tenant`,
  `scopes`). Secrets are never stored on the record, only opaque references
  (`credentialRef`, `mtlsCredentialRef`) resolved through a
  `CredentialProvider`.
- **`credential-store-encrypted-local`**: the default `CredentialProvider`,
  an AES-GCM encrypted local file keyed by a locally generated secret.
- **`client-sdk`**: `CdsHooksClient`. Given a resolved `ConnectionRecord`, it
  calls the payer's standard `GET {baseUrl}/cds-services` discovery endpoint
  and invokes a named hook, with both a typed (`callHook`) and a
  raw-passthrough (`callHookRaw`) response mode. It also includes:
  - **Authentication**, chosen by the record's `authType`:
    - `NONE`
    - `API_KEY`: `Authorization: Bearer <secret>`
    - `OAUTH2_CLIENT_CREDENTIALS`: client secret sent with
      `client_secret_basic`
    - `OAUTH2_PRIVATE_KEY_JWT`: a signed `private_key_jwt` client assertion
      (RFC 7523, as in SMART Backend Services)
    - `CDS_HOOKS_JWT`: the CDS Hooks 2.0 client JWT, signed per request

    OAuth2 access tokens are cached in memory until shortly before they
    expire, and a 401 drops the cached token and retries once. JWTs are signed
    with RS384 (RSA 2048+) or ES384 (EC P-384), picked from the PKCS#8 PEM key
    behind `credentialRef`. `Jwks` builds the public JWK Set to give the
    payer, and `PemKeys` reads PEM keys and certificates.
  - **Mutual TLS**, combinable with any `authType`: when a record sets
    `mtlsCredentialRef` (a PEM certificate chain plus private key), the client
    builds a TLS 1.2+ connection with that client certificate and also uses it
    for the OAuth2 token endpoint.
  - **Typed CRD 2.2.1 models** (`client.crd` package): `CrdHookContext`
    contexts for `order-sign`, `order-select`, `order-dispatch`,
    `appointment-book`, `encounter-start` and `encounter-discharge`;
    `CrdPrefetch` for the CRD prefetch keys; and `CoverageInformation` for
    parsing `ext-coverage-information` from the response. FHIR resources stay
    as Jackson `JsonNode`s (no HAPI FHIR dependency), and contexts check
    required elements and basic shapes, not full profile conformance.
- **`examples-quickstart`**: a runnable example that loads sample connection
  records from YAML, resolves a payer, and sends an `order-sign` request to an
  in-process mock CDS Hooks server on `http://localhost:8089` (there's no real
  payer sandbox to hit from a personal project).

## Building

Requires JDK 17+. Maven itself doesn't need to be installed; use the bundled
wrapper:

```sh
./mvnw verify                                   # build + all tests
./mvnw install -DskipTests                      # then, to run the demo:
./mvnw -pl examples-quickstart exec:java
```

### Testing against the HL7 CRD reference server

`CrdReferenceServerTest` runs the client against the
[HL7 Da Vinci CRD reference implementation](https://github.com/HL7-DaVinci/CRD).
It is skipped unless `CRD_RI_BASE_URL` is set. To run it locally with Docker:

```sh
docker build -t crd-ri https://github.com/HL7-DaVinci/CRD.git#master
docker run -d -p 18090:8090 crd-ri
CRD_RI_BASE_URL=http://127.0.0.1:18090/r4 ./mvnw -pl client-sdk -am test
```

## CI and code analysis

GitHub Actions workflows in `.github/workflows/`:

- **`ci.yml`**: `./mvnw verify` on JDK 17 and 21, on pushes to `master` and
  on pull requests.
- **`crd-reference-server.yml`**: builds the HL7 CRD reference server image,
  starts it, and runs the `client-sdk` tests against it. The server build is
  slow, so this runs weekly (Mondays 12:00 UTC) and on manual dispatch, not on
  every push.
- **`sonar.yml`**: the code analysis for this repo. It builds, runs the tests
  with JaCoCo coverage, and analyzes with
  [SonarCloud](https://sonarcloud.io), failing the check when the quality gate
  fails. It runs on pushes to `master` and on pull requests from this
  repository (not forks), and needs the `SONAR_TOKEN` repo secret. The
  SonarCloud organization and project key are set in the parent `pom.xml`.

The maintainer can also scan locally against a private self-hosted SonarQube
by overriding the `sonar.*` host and project key. That is optional and not
needed to contribute.

## Status

As of 2026-10-04, `./mvnw verify` passes on JDK 21 (compiled with
`--release 17`): 41 tests, of which the 2 reference-server tests are skipped
unless `CRD_RI_BASE_URL` is set. CI runs the same build on JDK 17 and 21, and
the quickstart runs end-to-end against the mock server.

Still missing (see also [DECISIONS.md](./DECISIONS.md)):

- Testing against a real payer's sandbox
  ([#1](https://github.com/dflippojr/fhir-crd-router/issues/1)). So far the
  client has only been run against the mock server and the HL7 CRD reference
  implementation.
- Publishing to Maven Central
  ([#2](https://github.com/dflippojr/fhir-crd-router/issues/2)). Nothing is
  published yet.

## License

MIT, see [LICENSE](./LICENSE).
