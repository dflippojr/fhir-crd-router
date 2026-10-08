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
(`credentialRef -> base64(iv || ciphertext)`). To audit key creation, credential
puts, removes and resolves, pass an `AuditSink` as a second constructor argument
and wrap the provider in `AuditedCredentialProvider`; see
[AUDIT.md](../directory-core/AUDIT.md).

```java
CredentialProvider credentials = new EncryptedLocalCredentialProvider(Path.of(".fhir-crd-router"));
credentials.put("payer-1-prod-key", "sk_live_...");
String secret = credentials.resolve("payer-1-prod-key").orElseThrow();
```
