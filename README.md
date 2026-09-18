# FHIR CRD Router

A small, personal, open-source Java library that resolves `payerId ->
connection record` for medical insurance payers' FHIR CRD (CDS Hooks)
endpoints, plus an optional client SDK that uses a resolved record to make
the actual CDS Hooks call.

This is **discovery/directory only** — it never touches patient data. See
[DECISIONS.md](./DECISIONS.md) for the scaffolding choices made to get this
building, and the `fhir-crd-payer-router` capsule in the personal memory
library for the full architecture rationale (why discovery-only, why
library-first, why the credential store is pluggable, etc.).

## Modules

- **`directory-core`** — `ConnectionRecord` model, `ConnectionStore`
  interface + a default flat-YAML-file implementation, `CredentialProvider`
  interface, and `PayerRouter` (the `payerId -> ConnectionRecord` resolver).
- **`credential-store-encrypted-local`** — default `CredentialProvider`
  implementation: an AES-GCM encrypted local file, keyed by a locally
  generated secret. `ConnectionRecord` only ever stores an opaque
  `credentialRef` into this (or another) provider — never a raw secret.
- **`client-sdk`** — `CdsHooksClient` plus typed CRD hook contexts and coverage-information parsing: given a resolved `ConnectionRecord`,
  calls the payer's standard `GET {baseUrl}/cds-services` discovery endpoint
  and invokes a named hook, with both a typed and a raw-passthrough response
  mode.
- **`examples-quickstart`** — a runnable example that loads sample
  connection records from YAML, resolves a payer, and calls an in-process
  mock CDS Hooks server (since there's no real payer sandbox to hit from a
  personal project).

## Building

Requires JDK 17+. Maven itself doesn't need to be installed — use the
bundled wrapper:

```sh
./mvnw verify                                   # build + all tests
./mvnw install -DskipTests                      # then, to run the demo:
./mvnw -pl examples-quickstart exec:java
```

CI (`.github/workflows/ci.yml`) runs `verify` on JDK 17 and 21.

## Local SonarQube (tower)

Analysis of this repo is **local/on-tower only**. Do not add a GitHub-hosted Action that talks to the homelab SonarQube (especially from pull requests). After `./mvnw verify`:

```powershell
D:\Docker\sonarqube\scan.ps1 -Path . -ProjectKey fhir-crd-router -Maven
```

Public GitHub CI can move to SonarCloud later. See `D:\Docker\sonarqube\README.md`.

## Status

Builds and passes tests (verified 2026-09-15 on JDK 21, compiled with
`--release 17`), and the quickstart runs end-to-end against the mock server.
Not yet published anywhere and not yet pointed at a real payer sandbox — see
[DECISIONS.md](./DECISIONS.md) for what's still missing.

## License

MIT — see [LICENSE](./LICENSE).
