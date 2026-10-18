# Inferno CRD client suite as a conformance judge

Investigation for [#97](https://github.com/dflippojr/fhir-crd-router/issues/97),
2026-10-17.

**Outcome: (a) it works, with limits.** The Inferno Da Vinci CRD test kit's
client suite runs headlessly in Docker. `InfernoCrdClientSuiteTest` drives it
with this library's `CdsHooksClient`. Inferno acts as the CRD payer server and
judges every request the client sends. The run finds one real gap in the
library, filed as [#128](https://github.com/dflippojr/fhir-crd-router/issues/128):
the SDK cannot send the CDS Hooks `extension` object, so it cannot send
`davinci-crd.requestedVersion`. The remaining failures come from the local
setup (no TLS, no EHR FHIR server) or from steps a library cannot do (show
cards to a user). They are recorded below with their reasons. The test
compares every Inferno verdict against that record.

## The kit

| | |
|---|---|
| Repository | [inferno-framework/davinci-crd-test-kit](https://github.com/inferno-framework/davinci-crd-test-kit) (maintained by the Inferno team at MITRE for ONC/CMS) |
| Version | v0.14.2 (released 2026-09-09), commit `35dd6ff5cde916e2b1c72f4ce5ac377e1e4fb491` |
| Framework | inferno_core 1.4.3 |
| License | Apache License 2.0 (MITRE NOTICE) |
| Suite used | `crd_client_v221`, "Da Vinci CRD Client v2.2.1 Test Suite", US Core 3.1.1 option |
| Spec | [CRD 2.2.1](https://hl7.org/fhir/us/davinci-crd/STU2.2/) and CDS Hooks (the kit cites the 2026Jan / 3.0.0 ballot text) |

The kit also has a v2.0.1 client suite and server suites for both versions.
The kit marks its tests as a **DRAFT** that "does not prove conformance". It
is still the only CRD client test suite maintained outside this repo.

### What the client suite checks

Inferno simulates two CRD services: one asks for the full
[standard prefetch](https://hl7.org/fhir/us/davinci-crd/STU2.2/foundation.html#standard-prefetch)
and one asks for a subset. For each hook group (1.2.1 to 1.2.6, one per CRD
hook) it waits for requests, answers them with mocked cards, and then checks:

- **Hook request shape**: structure and FHIR content of each request
  (`hook`, `hookInstance`, `context`, `fhirServer`, `fhirAuthorization`). The
  HL7 FHIR validator checks it against the CRD 2.2.1 profiles and logical
  models (`x.3.01`).
- **CRD version**: the `davinci-crd.requestedVersion` extension is `"2.2"`
  (`x.3.02`).
- **Prefetch**: resources conform to the CRD profiles (`x.3.03`), and the
  request carries exactly the requested keys (`x.3.04`).
- **Coverage**: the prefetched Coverage's payer is the payer registered for
  that service (`x.3.05`).
- **`fhirAuthorization`**: Inferno could fetch more data from `fhirServer`
  with the token (`x.3.06`), the granted scopes are the ones it asked for
  (`x.3.07`), and both endpoints use TLS (`x.3.08`).
- **JWT auth** (CDS Hooks "Trusting CDS Clients"): the bearer token decodes
  (`x.4.01`), the JWKS is available (`x.4.02`), the header has `alg`/`kid`/`typ`
  (`x.4.03`), and `iss`, `aud`, `exp`, `iat`, `jti` and the signature are
  valid (`x.4.04`).
- **Card handling**: a tester attests that the cards were shown to a user
  (`x.2.01`), Inferno's own responses are valid (`x.2.02`), and a
  coverage-information action was returned (`x.2.03`, order and appointment
  hooks).

Group 1.4 (Cross Hook) adds checks across every request: unique
`hookInstance` values, both the complete and subset prefetch seen,
Location address propagation, FHIRPath collections in prefetch templates,
and support for every coverage-information must-support element.

## How it runs

```sh
tools/inferno/start.sh       # clone the kit at the pinned commit, build, start on :18080
INFERNO_BASE_URL=http://localhost:18080 ./mvnw -B -ntp -pl client-sdk -am test \
    -Dtest=InfernoCrdClientSuiteTest -Dsurefire.failIfNoSpecifiedTests=false
tools/inferno/stop.sh
```

The **Inferno CRD client suite** workflow
(`.github/workflows/inferno-crd-client.yml`, `workflow_dispatch` only) runs
the same steps on a hosted runner and uploads `client-sdk/target/inferno/`
(`results.json` and `results.md`).

`tools/inferno/compose.override.yml` makes the kit's Docker Compose setup
reliable enough to script:

- It pins the helper images by digest. The kit's compose file uses `:latest`
  for nginx, redis, fhirpath and the HL7 validator.
- It serves Inferno on `127.0.0.1:18080`, not port 80.
- It sets `INITIALIZE_VALIDATOR_SESSIONS=false`. By default Inferno warms a
  validator session for every suite in the image at boot (every US Core
  version, both CRD versions). The validator then grew past 9 GB and was
  OOM-killed in the middle of a run. With sessions created on use, and the
  validator capped at 8 GB, it peaked at about 4.2 GB.
- It orders startup (nginx after inferno, inferno after redis) and restarts
  on failure. Without that, nginx exited with `host not found in upstream
  "inferno"`.
- It drops redis persistence. On a fresh checkout the redis user could not
  write the kit's `./data/redis` mount.

### What the harness does

1. It runs a warm-up session first (see [Reliability](#reliability)). Then it
   generates a throwaway P-384 key and builds the JWKS with `Jwks`. It
   creates two `ConnectionRecord`s with `AuthType.CDS_HOOKS_JWT`, one per
   simulated service, using a random `iss`.
2. It runs **1.1 Registration** through Inferno's JSON API (`/api/test_sessions`,
   `/api/test_runs`). Inputs: the `iss`, the raw JWKS, and the two payer
   Organization ids. The registration attestation is answered "true": the
   two records are this library's registration of Inferno's services.
3. It discovers both services with `discoverServices` and checks them with
   `CdsDiscoveryValidator`, which found no violations.
4. For each hook group, it sends the kit's own conformant CRD 2.2.1 request
   bodies (`client-sdk/src/test/resources/inferno/`) to both services through
   `callHook`. Each request gets a fresh `hookInstance`. It then follows
   Inferno's continuation link. The card-display attestation is answered
   **"false"**: a library has no user interface, so it cannot truthfully attest
   that cards were shown to a user.
5. It runs **1.4 Cross Hook** the same way, sending every hook again.
6. It reads every result, writes `target/inferno/results.{json,md}`, and makes
   one JUnit dynamic test per Inferno test. Each one compares the verdict
   with `expected-results.json`. An Inferno test that is new, missing or
   changed fails the build until the record is updated.

The fixtures carry their own prefetch, so the prefetch tests check that the
SDK sends the caller's prefetch through unchanged: key order, `null` values
and nested resources. They do not check that the SDK can work prefetch out
by itself. The harness also runs `PrefetchTemplates.expand` against each
service's templates and logs the result, without asserting on it. CRD's
standard templates use FHIRPath tokens
(`{{context.draftOrders.entry.resource.ofType(DeviceRequest).code.resolve().id}}`),
which `PrefetchTemplates` does not support. It reports them as unresolved,
as documented.

## Results

Source: `client-sdk/src/test/resources/inferno/expected-results.json`, which
records the verdict and the reason for each of the 115 tests the harness runs.
The verdicts are `pass` or `fail`; Inferno skipped none. In the last column,
**n/a** means not applicable to a library, and **env** means the local setup
cannot pass it.

Hook groups (`1.2.x`) and the cross-hook invocation group (`1.4.1`). Each cell is Inferno's verdict for that test in that group; `—` means the kit has no such test there.

| Test | Title | 1.2.1 appointment-book | 1.2.2 encounter-start | 1.2.3 order-select | 1.2.4 order-sign | 1.2.5 order-dispatch | 1.2.6 encounter-discharge | 1.4.1 cross-hook | Library verdict |
|---|---|---|---|---|---|---|---|---|---|
| x.1.01 | Client invokes the hook | pass | pass | pass | pass | pass | pass | pass | pass: The client invokes the hook (the requests reach Inferno, matched by JWT `iss`). |
| x.2.01 | Client displays returned decision support details to the user | fail | fail | fail | fail | fail | fail | fail | n/a: Attested **false** by design: a library has no UI to display cards. |
| x.2.02 | Hook responses have the correct structure and content | pass | pass | pass | pass | pass | pass | pass | pass: Inferno's responses to these requests validate (CRD logical model). |
| x.2.03 | Client supports the Coverage Information response type | pass | — | — | pass | pass | — | — | pass: A coverage-information systemAction was returned (the kit has this test only in these three groups). |
| x.3.01 | Hook requests have the correct structure and contents | pass | pass | pass | pass | pass | pass | pass | pass: Request structure and FHIR content validate against CRD 2.2.1 (HL7 validator). |
| x.3.02 | Hook requests contains the CRD version extension | fail | fail | fail | fail | fail | fail | fail | **fail**: **Real gap, #128**: no `extension` on `CdsHookRequest`, so `davinci-crd.requestedVersion` is never sent. |
| x.3.03 | Prefetched resources conform to the required CRD profiles | pass | pass | pass | pass | pass | pass | pass | pass: Prefetched resources conform to the CRD profiles. |
| x.3.04 | Hook requests include the requested prefetch data | pass | pass | pass | pass | pass | pass | pass | pass: Exactly the requested prefetch keys and data, for both the complete and the subset service. |
| x.3.05 | Prefetched coverages are valid | fail | fail | fail | fail | fail | fail | fail | env: Inferno resolves `Coverage.payor` through `fhirServer`; no EHR FHIR server in this setup. |
| x.3.06 | Client made additional FHIR data available during hook request processing | fail | fail | fail | fail | fail | fail | fail | env: Inferno fetches extra data through `fhirServer`; no EHR FHIR server in this setup. |
| x.3.07 | Hook requests grant the requested scopes | pass | pass | pass | pass | pass | pass | pass | pass: `fhirAuthorization.scope` grants the requested scopes. |
| x.3.08 | Hook request interactions use TLS | fail | fail | fail | fail | fail | fail | fail | env: Local kit and fixture `fhirServer` use `http`, not TLS. |
| x.4.01 | Bearer tokens can be decoded | pass | pass | pass | pass | pass | pass | pass | pass: The bearer token is a decodable JWT. |
| x.4.02 | JWKSs can be retrieved | pass | pass | pass | pass | pass | pass | pass | pass: The JWKS from `Jwks` is usable. |
| x.4.03 | Authorization token headers contain required information | pass | pass | pass | pass | pass | pass | pass | pass: JWT header has `alg` (ES384), `kid` and `typ: JWT`; `kid` is in the JWKS. |
| x.4.04 | Authorization token payloads have required claims and valid signatures | pass | pass | pass | pass | pass | pass | pass | pass: `iss`, `aud` (the exact service URL), `exp`, `iat`, `jti` and the signature are valid. |

Registration and cross-hook analysis:

| Test | Title | Result | Library verdict |
|---|---|---|---|
| 1.1.01 | CRD client registers with Inferno | pass | pass: the `iss`, raw JWKS and both payer Organization ids are accepted (warning: Inferno discourages a raw JWKS over a URL). |
| 1.1.02 | CRD client registers Inferno | pass | pass: attested **true**; the two `ConnectionRecord`s are the registration. |
| 1.4.2.01 | Client supports the Coverage Information response type | fail | n/a: Inferno's mocked responses do not carry every coverage-information must-support element (the kit says testers must supply custom responses), so this tests the payer side. |
| 1.4.3.01 | Client propagates addresses to child Location resources | pass | pass: Location addresses propagate (fixture content, sent through unchanged). |
| 1.4.3.02 | Client correctly interprets collections when substituting FHIRPath results in prefetch templates | pass | pass: a prefetch template with a multi-valued FHIRPath token was exercised (fixture content). |
| 1.4.3.03 | Client does not reuse hookInstance values | pass | pass: every request had a unique `hookInstance`. |
| 1.4.3.04 | Client can provide both the complete standard prefetch data set and a subset | pass | pass: the client served both the complete and the subset prefetch service. |

Totals: 115 Inferno tests; 79 pass, 36 fail. Of the failures, 7 are the real gap (#128, one per group). The other 29 are not applicable to a library or come from the local setup, as listed above.

## Reliability

- **Repeatable.** These runs were made on 2026-10-17 against the same kit
  build:

  | Run | Validator | Harness | Result |
  |---|---|---|---|
  | 1 | cold, no warm-up session yet | 756 s | 78 pass, 37 fail. It differs from the record only in `1.2.1.4.04` (`Signature has expired`, see below) |
  | 2 | warm | 91 s | 79 pass, 36 fail. Recorded as `expected-results.json` |
  | 3 | cold (container restarted), with warm-up | 637 s | all 115 verdicts match the record |
  | 4 | warm, `jti` removed from `JwtSigner` on purpose | 60 s | **7 red**: every `x.4.04`, `Token validation error: Missing jti` |
  | 5 | warm, code restored | 60 s | all 115 verdicts match the record |

  Run 4 shows the judge catches a real regression in the wire behaviour.
  Runs 3 and 5 show that a cold start and a warm start give the same
  verdicts.
- **Cold start.** On first use, the HL7 validator downloads and loads the
  CRD, US Core, VSAC and terminology packages, which takes about 10 minutes
  here. `RUN_TIMEOUT` is 30 minutes per wait for this reason.
- **JWT expiry is checked when the test runs, not when the request
  arrived.** `x.4.04` decodes the token with `exp` verified (60 s of
  leeway) after the group's slower validation tests finish. CDS Hooks JWTs
  live 5 minutes (`JwtSigner.LIFETIME`), and a cold validator takes longer
  than that (run 1). The harness therefore runs a throwaway warm-up session
  first (registration plus one encounter-start group, under its own `iss`),
  so the judged requests are analysed while their tokens are still valid.
- **Outside dependencies.** The validator uses `tx.fhir.org` for
  terminology, and the kit is built from source with RubyGems. A run needs
  internet access, and an outage there fails the run.
- **Memory.** The validator peaked at about 4.2 GB once sessions were
  created on use (8 GB cap). A hosted runner (16 GB) has room.

## Not applicable to a library, or not run

- **2 FHIR API** (US Core server read/search, CRD update visibility): this
  tests the EHR's own FHIR server, which a CRD client library does not have.
- **3 Visual Inspection and Attestation**: twelve attestations about the
  EHR product (logging, security, workflow integration, user display). They
  are not applicable to a library.
- **1.3 Scenarios** (long-running request, unknown response content,
  self-pay): each one needs the tester to watch a user workflow keep going,
  or to attest to how the UI handled the response. The SDK's part of these
  (timeouts, and ignoring unknown fields when parsing) is covered by its own
  unit tests.
- **`x.3.05` coverage and `x.3.06` data fetch**: Inferno reads the payer and
  extra data through the request's `fhirServer`. The fixtures point that at
  the kit's CRD server suite FHIR endpoint, which has no session in this
  setup. Passing these needs an EHR FHIR server, which a library does not
  have.
- **`x.3.08` TLS**: the local kit is served over `http`. The SDK supports
  `https` and mutual TLS. That is tested in its own suite, not here.

## Follow-ups

- [#128](https://github.com/dflippojr/fhir-crd-router/issues/128): add the
  request `extension` object. When it is fixed, the `x.3.02` rows in
  `expected-results.json` should become `pass`.
- Making this run a required gate is out of scope for #97. To do it: run the
  workflow on a schedule, or on PRs that touch `client-sdk`, keep the
  validator warm (cache `data/igs` and the validator's package cache), and
  serve Inferno behind a TLS proxy so `x.3.08` can pass.
- Upstream feedback for the kit: check JWT `exp` against the time the
  request was received; make nginx depend on inferno in `docker-compose.yml`.
