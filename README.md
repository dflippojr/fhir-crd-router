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
- **`client-sdk`** — `CdsHooksClient`: given a resolved `ConnectionRecord`,
  calls the payer's standard `GET {baseUrl}/cds-services` discovery endpoint
  and invokes a named hook, with both a typed and a raw-passthrough response
  mode.
- **`examples-quickstart`** — a runnable example that loads sample
  connection records from YAML, resolves a payer, and calls an in-process
  mock CDS Hooks server (since there's no real payer sandbox to hit from a
  personal project).

## Status

Scaffolded 2026-09-13, not yet built or tested — this machine only has JDK 8
and no Maven installed. See [DECISIONS.md](./DECISIONS.md) for what's needed
to actually build it, and what's still missing.

## License

MIT — see [LICENSE](./LICENSE).
