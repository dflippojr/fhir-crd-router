# directory-core

Core contracts and the default implementations:

- `ConnectionRecord` — immutable record for one payer+environment's endpoint
  and auth metadata. Built via `ConnectionRecord.builder()...build()`.
  `authType` sets app-layer auth (`NONE`, `API_KEY`,
  `OAUTH2_CLIENT_CREDENTIALS`, `OAUTH2_PRIVATE_KEY_JWT`, `CDS_HOOKS_JWT`).
  The optional `mtlsCredentialRef` adds mutual TLS on top of any of them. See
  the `client-sdk` README for which fields each auth type needs.
- `ConnectionStore` — pluggable persistence; `FileBasedConnectionStore` is
  the v1 default (flat YAML file, whole-file read/rewrite). Writes are atomic
  (temp file + move), so a crash never leaves a partial file, but there is no
  cross-process locking: one process must own the file.
- `CredentialProvider` — pluggable secret resolution; the default
  implementation lives in the sibling `credential-store-encrypted-local`
  module to keep crypto code out of the core module.
- `PayerRouter` — the actual "router": `resolve(payerId[, environment])`,
  v1 routes by explicit payer ID only.

## Example

```java
ConnectionStore store = new FileBasedConnectionStore(Path.of("connections.yaml"));
store.save(ConnectionRecord.builder()
        .payerId("PAYER-1")
        .environment(Environment.PRODUCTION)
        .baseUrl("https://payer.example.com/cds")
        .authType(AuthType.API_KEY)
        .credentialRef("payer-1-prod-key")
        .igVersion("crd-2.0.1")
        .build());

PayerRouter router = new PayerRouter(store);
ConnectionRecord record = router.resolve("PAYER-1");
```

## Recording a verified connection

`lastVerifiedAt` records when a connection last passed a check. Nothing sets it
automatically. `record.withLastVerifiedAt(instant)` returns a copy with only that
field changed (`updatedAt` keeps its value); save the copy to record it. The
`client-sdk` README's "Verifying a connection" section shows the check that
produces the instant:

```java
ConnectionVerification report = client.verify(record);
if (report.ok()) {
    store.save(record.withLastVerifiedAt(report.checkedAt()));
}
```

Through `AuditedConnectionStore`, that save is recorded as `connection.update`
with `lastVerifiedAt` as the only changed field.
## Audit foundation

Optional actor-attributed JSONL history and the owner read/export API are documented
in [AUDIT.md](AUDIT.md). It is opt-in: `AuditedConnectionStore` and
`AuditedCredentialProvider` wrap the stores you already use, and the plain
constructors stay audit-disabled.
