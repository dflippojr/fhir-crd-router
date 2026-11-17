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
  One entry this version cannot read (a missing required field, or a property
  or enum constant from a newer version) does not break the others: other
  payers resolve, a lookup of that entry's payer or key throws
  `InvalidConnectionRecordException`, `invalidEntries()` lists it, and writes
  keep it, and any unknown field, as read. See "Unreadable entries" below.
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
## Unreadable entries

`FileBasedConnectionStore` binds each list entry on its own. An entry it cannot
bind stays in the file and out of `findAll()`:

```java
for (FileBasedConnectionStore.InvalidEntry bad : store.invalidEntries()) {
    // index, payerId and environment (null where unreadable), and problem:
    // the exception class, e.g. UnrecognizedPropertyException
}
```

`resolve` of that entry's key, and `findByPayerId` of its payer, throw
`InvalidConnectionRecordException` (a `RouterException`) with the payer,
environment and problem class, never a field value. To repair it, `save` a
complete record with the same key, which lays its fields over the stored entry
in place, or `delete` the key. A field this version does not know is kept by
both, so an entry a newer version wrote stays unreadable here after an older
writer's update. An entry whose environment this version does not know matches
no key, so only a hand edit removes it. `save` and `delete` also refuse,
naming the entry, while an entry they would write holds an explicit YAML tag
that disagrees with its plain text (`environment: !!float 2`): the writer
cannot keep the tag, and dropping it would change how the entry binds. A
number with a leading zero (`environment: 02`, read as octal 2) is written as
its field's value in a readable entry, so it binds as before, and refused
where its type is unknown (an unreadable entry, or an unknown field). A
duplicate mapping key and a native YAML type id (`!<limit>`, as a newer
version may write) are refused the same way. Saving over the affected field,
or deleting the entry, still works.

## Audit foundation

Optional actor-attributed JSONL history and the owner read/export API are documented
in [AUDIT.md](AUDIT.md). It is opt-in: `AuditedConnectionStore` and
`AuditedCredentialProvider` wrap the stores you already use, and the plain
constructors stay audit-disabled.
