# FHIR CRD Router

A small, personal, open-source Java library that resolves `payerId ->
connection record` for medical insurance payers' FHIR CRD (CDS Hooks)
endpoints, plus an optional client SDK that uses a resolved record to make
the actual CDS Hooks call.

The router is **discovery/directory only**: it never touches patient data.
Only the optional client SDK talks to a payer. See
[DECISIONS.md](./DECISIONS.md) for the design and scaffolding decisions made
so far.

## Modules

- **`directory-core`**: `ConnectionRecord` model, `ConnectionStore`
  interface with a default flat-YAML-file implementation
  (`FileBasedConnectionStore`), `CredentialProvider` interface, and
  `PayerRouter` (the `payerId -> ConnectionRecord` resolver). A record
  never holds a secret, only opaque `credentialRef` / `mtlsCredentialRef`
  references into a `CredentialProvider`. It also holds the opt-in
  `core.audit` package: an append-only JSONL audit trail, store and
  credential wrappers, and an owner read/export API
  (see [AUDIT.md](./directory-core/AUDIT.md)).
- **`credential-store-encrypted-local`**: the default `CredentialProvider`,
  an AES-GCM encrypted local file keyed by a locally generated secret.
  It caches the parsed ciphertext (never plaintext) and checks only the
  file's last-modified time, size and file key on each `resolve`, reading
  the file again only when those change. The file bytes are also compared
  at least every 30 seconds (configurable with the `Duration` constructor
  argument; `Duration.ZERO` compares on every call), so an outside edit
  that keeps the same size and modified time shows up within that interval.
- **`client-sdk`**: `CdsHooksClient`. Given a resolved `ConnectionRecord`, it
  calls the payer's `GET {baseUrl}/cds-services` discovery endpoint and
  invokes a named hook, with a typed (`callHook`) and a raw JSON
  (`callHookRaw`) response mode.
  - **Authentication** (`AuthType` on the record):
    - `NONE` and `API_KEY` (bearer secret).
    - `OAUTH2_CLIENT_CREDENTIALS` with `client_secret_basic`.
    - `OAUTH2_PRIVATE_KEY_JWT`: client credentials with an RFC 7523 signed
      client assertion, as in SMART Backend Services.
    - `CDS_HOOKS_JWT`: the CDS Hooks 2.0 client JWT, signed per request.

    Tokens are cached in memory until shortly before `expires_in`, and a
    401 triggers one retry with a fresh token. An API key or OAuth2 access
    token must be an RFC 6750 `b64token` (letters, digits, `-._~+/`, then
    optional `=` padding); anything else, such as a key saved with a trailing
    newline, fails with a `RouterException` before the payer is called, and an
    access token like that is never cached. JWTs are signed with RS384
    (RSA 2048+) or ES384 (EC P-384), chosen from the key; private keys are
    PKCS#8 PEM. `Jwks` builds the public JWK Set to give a payer, and
    `PemKeys` reads keys and certificates.
  - **Diagnostics and resilience**: typed `PayerCallException` errors with
    configurable timeouts, an opt-in `Retry-After` retry policy, redacted and
    metadata-only `PayerExchangeListener`s, `discoverServicesRaw` with
    `CdsDiscoveryValidator`, and `verify(record)` connection checks that
    report instead of throwing. See the [client-sdk README](./client-sdk/README.md).
  - **Mutual TLS** is a transport setting rather than an auth type: a record
    with an `mtlsCredentialRef` (PEM certificate chain plus key) gets its own
    TLS 1.2+ client, combinable with any of the auth types above.
  - **Typed CRD 2.2.1 models**: hook contexts for all six CRD hooks
    (`order-sign`, `order-select`, `order-dispatch`, `appointment-book`,
    `encounter-start`, `encounter-discharge`), CRD prefetch keys
    (`CrdPrefetch`), `fhirServer`/`fhirAuthorization` on requests, typed
    card source/topic and `systemActions` on responses, discovery prefetch
    templates, and `CoverageInformation` parsing. FHIR resources stay as
    Jackson `JsonNode`s; there is no HAPI FHIR dependency.
- **`examples-quickstart`**: a runnable example that loads sample connection
  records from YAML, resolves a payer, and calls an in-process mock CDS
  Hooks server on `http://localhost:8089`.

## Building

Requires JDK 17+. Maven itself doesn't need to be installed; use the
bundled wrapper:

```sh
./mvnw verify                                   # build + all tests
./mvnw install -DskipTests                      # then, to run the demo:
./mvnw -pl examples-quickstart exec:java
```

### Testing against the CRD reference server

`CrdReferenceServerTest` runs the client against the
[HL7 Da Vinci CRD reference implementation](https://github.com/HL7-DaVinci/CRD).
It is skipped unless `CRD_RI_BASE_URL` is set. To run it locally with Docker:

```sh
docker build -t crd-ri "https://github.com/HL7-DaVinci/CRD.git#$(cat .github/crd-ri.ref)"
docker run -d -p 18090:8090 crd-ri
CRD_RI_BASE_URL=http://127.0.0.1:18090/r4 ./mvnw -pl client-sdk -am test
```

The suite checks required discovery fields (`id`, `hook`, `description`) and
parses every service and prefetch template into `CdsServiceDescriptor`. Non-CRD
hooks are named in the output and still checked for discovery conformance.

- `order-sign`: synthetic Medicare Part A orders for hospital beds (HCPCS E0250,
  HospitalBedsAndAccessories) and home oxygen (HCPCS E0424, HomeOxygenTherapy).
  Checks rule matching and parsed cards/coverage information, without asserting
  the CQL-dependent coverage decision.
- `order-select`, `order-dispatch`, `appointment-book`, `encounter-start`, and
  `encounter-discharge`: one request per advertised hook using `CrdHookContext`,
  with synthetic resources and RI prefetch bundles; checks response parsing.
  These requests use a synthetic device code outside the RI rule catalog.
  Each absent hook is skipped with its name in the output.
- Wire edge cases, all on `order-sign`: prefetch keys with no data sent as
  `null` (CDS Hooks 2.0 requires it); `fhirServer` and `fhirAuthorization` in
  the request; service ids with `/`, `..`, `?` or `#`, which must stay one
  encoded path segment and so reach no service; and a context with the wrong
  JSON type, which must come back as an HTTP 400 `PayerCallException`.

CI runs this suite on every PR (the `crd-ri` job) against the RI commit pinned
in `.github/crd-ri.ref`; see DECISIONS.md, "CRD reference server pin".

### CI

GitHub Actions runs two workflows:

- **CI** (`.github/workflows/ci.yml`) runs on every pull request and every
  push to `master`, with five jobs:
  - `build`: `./mvnw verify` on JDK 17 and 21. `verify` includes the JaCoCo
    coverage floor (line and branch, per module; see the parent `pom.xml`).
  - `sonar`: the SonarCloud analysis for this repo. It builds and tests on
    JDK 21, uploads JaCoCo coverage, and fails when the quality gate fails.
    It needs the `SONAR_TOKEN` repo secret and is skipped on fork PRs. The
    organization and project keys are in the parent `pom.xml`.
  - `crd-ri`: builds the HL7 CRD reference server from the commit in
    `.github/crd-ri.ref` (cached by that commit), starts it, and runs the
    `client-sdk` tests against it. It fails if `CrdReferenceServerTest`
    skipped anything.
  - `fhir-validator`: runs `fhir-validator/run.sh` (the official HL7 FHIR
    validator) and fails if a recorded verdict changed; see DECISIONS.md,
    "Differential testing against the official validator".
  - `gate`: always runs, and passes only when `build`, `sonar`, `crd-ri` and
    `fhir-validator` all succeeded. It is the one check to require.

  A new push to a PR cancels that PR's older run; runs on `master` are never
  cancelled.
- **CRD reference server drift** (`.github/workflows/crd-reference-server.yml`):
  runs `CrdReferenceServerTest` against RI `master` weekly (Mondays 12:00 UTC)
  and on manual dispatch. On failure it opens or comments on the "CRD RI
  master drift" issue; on success with a newer RI commit it opens a PR that
  bumps the pin.

Dependabot (`.github/dependabot.yml`) checks Maven dependencies and GitHub
Actions weekly and opens at most 3 pull requests per ecosystem, labeled
`dependencies`. The Jackson artifacts are grouped into one pull request.
Nothing auto-merges: CI and SonarCloud decide whether each update is safe, and
the owner merges. Changes to the `--release 17` baseline or the JDK matrix are
deliberate issues, not Dependabot pull requests. Dependabot-triggered runs do
not receive repository secrets, so the `sonar` job has no `SONAR_TOKEN` on
these pull requests (see the PR checks for how it ends).

A local SonarQube scan against a self-hosted server is optional and only for
the maintainer. The `sonar` job analyzes through the Maven scanner,
which does not read the root `sonar-project.properties`.

## Status

- `./mvnw verify` passes. The reference-server suite is skipped unless
  `CRD_RI_BASE_URL` is set. The code compiles with
  `--release 17`, and CI builds it on JDK 17 and 21.
- The quickstart runs end-to-end against its mock server.
- The client has been tested against the HL7 Da Vinci CRD reference
  implementation, but not yet against a real payer sandbox
  ([#1](https://github.com/dflippojr/fhir-crd-router/issues/1)).
- Not published anywhere yet; Maven Central publishing is
  [#2](https://github.com/dflippojr/fhir-crd-router/issues/2).

See the "Not yet done" section of [DECISIONS.md](./DECISIONS.md) for other
known gaps.

## License

MIT, see [LICENSE](./LICENSE).
