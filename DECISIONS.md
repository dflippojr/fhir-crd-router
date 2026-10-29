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

## CRD reference server pin (2026-10-16)

The HL7 Da Vinci CRD reference implementation is the one check here that this
repo's author did not write, so it now runs on every PR and every push to
`master` (the `crd-ri` job in `ci.yml`, required through `gate`), not weekly.

- **Pinned.** CI builds the RI from the commit in `.github/crd-ri.ref`, now
  `43547c4e69052df4d3532972e4bd03f8d5317d13` (RI `master` on 2026-07-21). A
  red `crd-ri` run therefore means our change broke interop, not that the RI
  changed. The image is cached in `actions/cache` keyed by that commit, so only
  the first run after a bump builds it.
- **Drift.** `crd-reference-server.yml` runs the same tests against RI
  `master` every Monday. On failure it opens, or comments on, one issue
  titled "CRD RI master drift" listing the failing tests. On success with a
  newer commit than the pin it opens a PR that bumps the pin.
- **Bumping the pin.** Merge the drift job's PR, or by hand: put the new commit
  in `.github/crd-ri.ref`, replace the old commit wherever it is quoted
  (`git grep <old sha>`), and open a PR; its `crd-ri` job is the proof. A
  PR opened by the workflow token does not start CI, so close and reopen it.
  If the drift issue is open instead, either fix the client (the RI is right)
  or record the RI difference in this file and adapt the test.
- **RI quirk.** The pinned RI answers an `order-sign` context missing its
  required fields with HTTP 500 (it crashes), but a context with the wrong
  JSON type with 400. The error-semantics test uses the second, which CDS
  Hooks 2.0 allows ("MAY return other HTTP statuses, specifically 4xx and
  5xx").
- **No new auth.** The tests call the RI with `AuthType.NONE`, plus
  `fhirServer`/`fhirAuthorization` in the request body, which the client
  already supports. CDS Hooks client JWTs stay a separate decision.

## Inferno CRD client suite as a second judge (2026-10-17)

- The Inferno Da Vinci CRD test kit (v0.14.2, pinned in
  `tools/inferno/start.sh`) runs headlessly. `InfernoCrdClientSuiteTest`
  drives its CRD 2.2.1 client suite through Inferno's JSON API, using the
  kit's own conformant request bodies as fixtures. Evidence and per-test
  results are in [docs/inferno.md](./docs/inferno.md).
- The test asserts each Inferno verdict against a recorded expectation
  (`expected-results.json`), not "all pass". Some tests can never pass for a
  library run locally: card display to a user, the EHR's FHIR server, TLS on
  a local kit. A recorded expectation still catches a regression in any test
  that does pass.
- Attestations are answered truthfully. Registration is attested "true",
  because the `ConnectionRecord`s are the registration. Card display is
  attested "false", because a library has no UI to show cards in.
- It is manual dispatch only, not a gate. The kit build plus a cold HL7
  validator takes many minutes, and the validator needs `tx.fhir.org`.
- First finding: the SDK cannot send the request `extension` object, so it
  cannot send `davinci-crd.requestedVersion` or `davinci-crd.configuration`
  (#128).

## Only ACTIVE connections are routable (2026-10-22, #104)

`PayerRouter.resolve` returns a record only when its status is `ACTIVE`.
`INACTIVE` and `DEPRECATED` both throw the same "No active connection"
`RouterException` as a missing record, so no hook call goes to a payer
marked inactive. Before this only `DEPRECATED` was refused. The owner chose
this (option A on #104). `CdsHooksClient.verify` takes the record directly
and runs on any status, so a connection can be checked before it is
switched back to `ACTIVE`.

## Payer URLs must be https, except loopback (2026-10-29, #156)

`baseUrl`, `tokenEndpoint` and `jwksUrl` must be absolute `https` URLs with a
host. `http` is allowed only to a loopback host (`localhost`, `127.0.0.0/8`,
`[::1]`), decided from the literal host without DNS. The owner chose this on
#156: Q1 (A), Q2 (a), Q3 (i).

- **Why every environment.** [CDS Hooks 2.0, Security and
  Safety](https://cds-hooks.hl7.org/2.0/#security-and-safety) makes TLS a
  MUST with no sandbox carve-out, and sandbox and staging records often carry
  real-looking secrets. Before this, a `PRODUCTION` record with an `http`
  `baseUrl` sent its API key or bearer token in cleartext, and a set
  `mtlsCredentialRef` changed nothing: the JDK presents no client certificate
  over `http`. Loopback stays allowed for the quickstart, the CRD reference
  server and Inferno jobs, and the tests.
- **Enforced in the client, not the record.** `CdsHooksClient`,
  `OAuth2TokenClient` and `JwtSigner` check the URLs and throw
  `EndpointUrlException` before any credential read or request.
  `ConnectionRecord` still accepts any string, because
  `FileBasedConnectionStore` parses the whole file: a constructor check would
  let one old `http` record break `resolve` for every payer.
- **`jwksUrl` too.** The SDK never fetches it, but it goes into the `jku`
  header, and a payer fetching our keys over `http` lets a network attacker
  swap them. One rule for every URL on the record is easier to state.
- **Malformed URLs fail the same way.** A URL that is not absolute, has no
  host or has a scheme other than `http`/`https` throws the same exception
  naming the field and `payerId`, instead of a bare `IllegalArgumentException`
  from `URI.create`. `verify` reports it with no phase. Neither repeats the
  URL, which may hold userinfo or a secret in its query.
- **Redirect-following clients are refused, not followed by hand.** Only the
  record's URLs are checked, so a supplied `HttpClient` that follows
  redirects would let an `https` payer or token endpoint answer 307 to an
  `http` URL and have the JDK resend the POST, credentials included, in
  cleartext. `CdsHooksClient` and `OAuth2TokenClient` refuse a client whose
  `followRedirects()` is not `NEVER` with `IllegalArgumentException`, in the
  constructor and on every `fetchAccessToken`, before any credential is read
  or cached token returned. Following redirects in the SDK and checking each
  `Location` was the alternative, but CDS Hooks and RFC 6749 token calls have
  no need for redirects, and refusing is one check with nothing to get wrong
  about which headers to carry. The JDK default and every SDK-built client
  already use `NEVER`.
- **`fetchAccessToken` checks `jwksUrl` first.** Called directly, it checks
  `tokenEndpoint` and, for `OAUTH2_PRIVATE_KEY_JWT`, `jwksUrl` before the
  cache lookup, since `jwksUrl` is not in the cache key, and before the
  secret supplier runs, so a failing credential provider cannot hide the
  refusal. `EndpointUrls.requireTokenUrls` is the shared check, also used by
  `CdsHooksClient`'s preflight.

## Not yet done

- No publishing config (Maven Central / GitHub
  Packages).
- No real payer has been contacted. The client has been tested against the
  HL7 Da Vinci CRD reference implementation running locally in Docker, but
  not against any payer's sandbox.
- Typed contexts don't validate against full FHIR profiles, and FHIR
  resources are untyped `JsonNode`s.

## Differential testing against the official validator (2026-10-17, #96)

`CoverageInformationValidator` is hand-written, so CI also asks HL7's own
validator. The `fhir-validator` job in `ci.yml` (part of `gate`) runs
`fhir-validator/run.sh`. The script downloads a pinned `validator_cli.jar`
(7.0.2, checked against its SHA-256) and validates two sets of resources
against `hl7.fhir.us.davinci-crd#2.2.1`:

- the corpus in `client-sdk/src/test/resources/coverage-information/cases`;
- every FHIR resource inside the test fixtures (`crd-ri/*.json`, and the
  quickstart's `mock-payer/*.json`).

The job rewrites the recorded verdicts and fails if they changed.
`CoverageInformationDifferentialTest` then requires our verdict to match the
official one on every corpus case.

- **HAPI stays out of the build.** The validator runs as a CI tool, not a
  Maven dependency, so the library keeps its `JsonNode` design (see "Typed
  CRD models").
- **No terminology server** (`-tx n/a`). The verdicts are reproducible and
  need no network beyond the package download. The coverage-information
  bindings are all to CRD's own code systems, which the validator checks
  locally.

Where we disagree on purpose (listed in `known-differences.json`):

- **Legacy `identifier` is a warning.** The reference implementation sends it
  in place of `coverage-assertion-id`, so we warn rather than fail; the
  official validator fails it.
- **The reference implementation's `coverageInfo` is a warning** (owner
  decision on #125, 2026-10-17). An undefined relative sub-extension url is
  an error, as the official validator's `Extension_EXT_SubExtension_Invalid`:
  open slicing admits only absolute urls. The reference implementation sends
  `coverageInfo`, a relative url CRD 2.2.1 does not define, so we warn about
  it like `identifier`, and reference server responses are not flagged as
  errors. `unknown-ri-coverage-info` stays in `known-differences.json`
  because we still call it valid; its `warning` path makes the differential
  test require the warning.
- **`crd-ci-q4` follows its text, not its FHIRPath.** The expression is
  `A and B implies C`. When `pa-needed` is not `satisfied`, `A` is empty, so
  `{} implies false` is empty and the invariant fails. Read literally, it
  forbids `doc-purpose = withpa` on every extension, including
  `pa-needed = auth-needed`, where withpa is the point. We check what the text
  says: withpa is wrong only after `satisfied` or `no-auth`.
- **The coverage reference must name a Coverage.** The official validator does
  not check the type of an unresolved literal reference, so it accepts
  `Patient/pat-1`. We reject it, because the profile's target is Coverage.

Disagreements that are our bugs: none open. #126 (we did not check inside
`detail`) is fixed, and `detail-missing-code` now agrees.

The reference implementation's response fixture fails the official
validator, as recorded above: legacy names, no `covered` or `date`, and a
DeviceRequest without `code` or `subject`. That is expected, and
`fixture-verdicts.json` records it.

## Gate guard (2026-10-18, #94)

CI's own checks can be weakened by the pull request they judge: delete a
test, add `@Disabled`, lower a JaCoCo `<minimum>`, or edit `ci.yml`. The
shared gate guard from `dflippojr/.github` flags those changes, and the
owner's `gate-change-approved` label is the only way past it.

- **Two copies, one trusted.** `ci.yml`'s `gate-guard` job runs on
  `pull_request`, so it comes from the pull request's head and a pull
  request can replace it with a green no-op. It stays inside `gate` as an
  early signal. The judge is `gate-guard-target.yml`: under
  `pull_request_target` GitHub runs it as it is on `master`, it fetches the
  pull request's commits as git objects and reads their diff, and it never
  checks out or runs pull request code. It posts the `gate-guard` check run,
  which the `master` ruleset requires next to `gate`.
- **Approval is bound to the newest push.** The trusted copy counts the
  label only when the owner's label event is later than GitHub's recorded
  push of the head commit, so a push after an approval needs a new one. The
  `ci.yml` copy only checks who applied the label.
- **Pinned by full SHA.** Both `uses:` lines and both `guard-ref`s name the
  same commit of `dflippojr/.github` main, so the script that judges a pull
  request is the one that was reviewed. Move all four together.
- **Known limit.** The required check is bound to the GitHub Actions app,
  not to this workflow. A pull request that adds a job with `checks: write`
  could overwrite or republish a `gate-guard` check run. Closing that needs a
  separate GitHub App identity for the guard (dflippojr/.github#24).

## Corpus edit check (2026-10-22, #131)

AGENTS.md says never to edit a corpus case to make it agree. The
`fhir-validator` and `crd-ri` jobs catch a changed verdict, but not a case
rewritten so that both sides agree. `.github/scripts/corpus-edit-check.sh`
turns the rule into a check. CI's `corpus-edit` job runs it on every pull
request, and it is one of `gate`'s needs.

- **What counts.** The corpus is
  `client-sdk/src/test/resources/coverage-information/cases/` and
  `client-sdk/src/test/resources/crd-ri/`. Modifying, renaming or deleting a
  file there fails the check unless the same diff, taken from the merge
  base, changes `known-differences.json` or `DECISIONS.md`. Adding a case
  always passes.
- **Escape hatch, not approval.** The owner chose a diff check in this repo
  over the shared gate guard's protected paths. Writing the reason down is
  the price of an edit, and a reviewer reads that reason. No label is
  needed.
- **Pull requests only.** A push to `master` has no base to compare with, so
  the job is skipped there and `gate` accepts that skip on a push.
- **The check runs from the base commit.** The job checks out the pull
  request's base commit apart from the pull request and runs the check and
  its test from there; the pull request's checkout is only the repository
  they inspect. So a pull request that edits a case and turns both scripts
  into no-ops still fails: its copies never run on it. A change to the
  scripts takes effect once it is merged, after review. The gate guard flags
  edits to `ci.yml`, which holds that wiring, but not `.github/scripts/`, so
  the check guards its own presence: a pull request that deletes or renames
  `corpus-edit-check.sh` or its test fails, and no escape hatch allows it.
  Without that, a merged deletion would leave the next pull request's base
  with no check. The one fallback is a base older than the check, the case
  for the pull request that adds it: the job then runs the pull request's
  copy and says so in a warning. To retire the check, remove the job from
  `ci.yml` first, which needs the owner's `gate-change-approved`.
- **Paths are read NUL by NUL.** The check reads `git diff -z` one
  NUL-terminated field at a time, and prints paths shell-quoted. A file name
  may contain a newline; split into lines, an added file named
  `a<LF>M<LF>DECISIONS.md` would pose as a changed `DECISIONS.md` and unlock
  the escape hatch.
