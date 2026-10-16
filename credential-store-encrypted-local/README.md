# credential-store-encrypted-local

Default `CredentialProvider`: AES-256-GCM, key generated on first use and
stored next to the encrypted secrets file. Zero external dependencies —
appropriate for a solo personal deployment, not a substitute for a real
secrets manager.

To use Vault / AWS Secrets Manager / Azure Key Vault instead, implement
`CredentialProvider` in a new sibling module and pass that implementation
wherever this one would otherwise be wired in — `ConnectionRecord` never
knows or cares which provider resolved its `credentialRef`.

Files under the base directory: `key.bin` (the AES key) and `secrets.properties`
(`credentialRef -> v2:base64(iv || ciphertext || tag)`). Both are created owner-only (mode 600
where POSIX permissions apply). `secrets.properties` is never rewritten in place: each
write goes to a temporary file in the same directory and is moved over the old one, so
readers see the old or the new complete file and a crash keeps the previous content.
`key.bin` is created only by a `put` on a store with no entries and never replaces an
existing file, so two instances starting on a fresh directory end up sharing one key.
`resolve` never creates a key. If `key.bin` is lost while entries remain, both `resolve`
and `put` fail with "Local credential key is missing" until the original `key.bin` is
restored; a `key.bin` that is not exactly 32 bytes and a malformed entry also fail with an
`IllegalStateException` that names the problem.

Each entry is encrypted with its `credentialRef` as AES-GCM associated data, so an entry
that is copied or moved under another reference (a hand edit, a bad merge, a mixed-up
restore) fails with "Failed to decrypt credential" instead of resolving to another
reference's secret. The `v2:` prefix marks that format. Entries written by earlier versions
have no prefix and no binding: they still resolve, and the next `put` or `remove` rewrites
all of them in the bound format. An old entry that cannot be decrypted is left as it is.

`put` and `remove` are safe across instances and processes on one directory: they hold an
exclusive OS file lock on `secrets.lock` (a sidecar file, created empty and kept) while they
re-read `secrets.properties`, change it and move the new file into place, so concurrent
writers wait for each other and no write is lost. A writer waits without a timeout. Calling
`put` or `remove` on the same directory from inside a `put` or `remove` (from an audit sink,
say) fails with an `IllegalStateException` rather than deadlocking.

To audit key creation, credential
puts, removes and resolves, pass an `AuditSink` as a second constructor argument
and wrap the provider in `AuditedCredentialProvider`; see
[AUDIT.md](../directory-core/AUDIT.md).

```java
CredentialProvider credentials = new EncryptedLocalCredentialProvider(Path.of(".fhir-crd-router"));
credentials.put("payer-1-prod-key", "sk_live_...");
String secret = credentials.resolve("payer-1-prod-key").orElseThrow();
```
