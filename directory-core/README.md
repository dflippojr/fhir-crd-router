# directory-core

Core contracts and the default implementations:

- `ConnectionRecord` — immutable record for one payer+environment's endpoint
  and auth metadata (schema per the capsule's "Draft Connection Record
  Schema"). Built via `ConnectionRecord.builder()...build()`.
- `ConnectionStore` — pluggable persistence; `FileBasedConnectionStore` is
  the v1 default (flat YAML file, whole-file read/rewrite).
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
