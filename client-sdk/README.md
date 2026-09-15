# client-sdk

Given a resolved `ConnectionRecord` (from `PayerRouter.resolve(...)`), calls
the payer directly — the router itself never makes this call.

- `discoverServices(record)` — hits the payer's standard
  `GET {baseUrl}/cds-services` and returns the parsed service list. Nothing
  is cached or curated by the router; this always asks the payer live.
  Each `CdsServiceDescriptor` includes the payer's `prefetch()` templates.
- `callHook(record, serviceId, request)` — typed response (`cards()`,
  `systemActions()`, `coverageInformation()`) plus `rawJson()` passthrough on
  the same `CdsHookResponse`.
- `callHookRaw(record, serviceId, request)` — raw `JsonNode` only.

## CRD requests and responses

Typed hook contexts follow the CRD 2.2.1 logical models, in
`io.github.dflippojr.fhircrdrouter.client.crd`:

| Record | Hook | Required |
| --- | --- | --- |
| `CrdHookContext.OrderSign` | `order-sign` | `userId`, `patientId`, `draftOrders` (Bundle) |
| `CrdHookContext.OrderSelect` | `order-select` | `userId`, `patientId`, `draftOrders` (Bundle) |
| `CrdHookContext.OrderDispatch` | `order-dispatch` | `patientId`, `dispatchedOrders` (1+) |
| `CrdHookContext.AppointmentBook` | `appointment-book` | `userId`, `patientId`, `appointments` (Bundle) |
| `CrdHookContext.EncounterStart` | `encounter-start` | `userId`, `patientId`, `encounterId` |
| `CrdHookContext.EncounterDischarge` | `encounter-discharge` | `userId`, `patientId`, `encounterId` |

FHIR resources stay as Jackson `JsonNode`s, so there's no HAPI FHIR
dependency. The records validate required fields, `[ResourceType]/[id]`
references, and that bundles are Bundles. They don't validate full FHIR
profiles.

```java
CdsHookRequest request = CdsHookRequest.of(
        new CrdHookContext.OrderSign("Practitioner/prac-1", "pat-1", null, draftOrdersBundle),
        CrdPrefetch.builder()
                .patient(patient)
                .coverage(coverageBundle)
                .put("somePayerSpecificKey", otherBundle) // whatever discovery asked for
                .build());

CdsHookResponse response = client.callHook(record, serviceId, request);
for (CoverageInformation info : response.coverageInformation()) {
    info.covered(); info.paNeeded(); info.docNeeded(); info.coverageAssertionId();
}
```

To give the payer access to your FHIR server as well, use
`request.withFhirServer(url, new CdsHookRequest.FhirAuthorization(token, ...))`.

**Prefetch keys vary by payer.** CRD recommends keys like `patient` and
`coverage`, but the HL7 reference implementation asks for its own keys
(`deviceRequestBundle`, `coverageBundle`, ...). Build prefetch from what the
payer's discovery response lists.

**Coverage information shows up in more than one place.** CRD 2.x returns it
as an `update` system action carrying the `ext-coverage-information`
extension. The reference implementation puts it inside card suggestion
actions instead, and uses older sub-extension names (`identifier` rather than
`coverage-assertion-id`). `coverageInformation()` searches both places and
accepts both names.

## Testing against the HL7 CRD reference implementation

`CrdReferenceServerTest` runs only when `CRD_RI_BASE_URL` is set:

```sh
docker build -t crd-ri https://github.com/HL7-DaVinci/CRD.git#master
docker run -d -p 18090:8090 crd-ri
CRD_RI_BASE_URL=http://127.0.0.1:18090/r4 ./mvnw -pl client-sdk -am test
```

The `CRD reference server` GitHub Actions workflow does the same thing weekly
and on demand. Use host port 18090, not 8090: 8090 is often taken by other
local services, and `localhost` can hit a different listener over IPv4 than
over IPv6.

## Authentication

App-layer auth comes from `record.authType()`. Mutual TLS is configured
separately (next section), so it can be combined with any of these.

| authType | What is sent | Record fields | `credentialRef` resolves to |
| --- | --- | --- | --- |
| `NONE` | No `Authorization` header. | | |
| `API_KEY` | `Authorization: Bearer <secret>` | | the API key |
| `OAUTH2_CLIENT_CREDENTIALS` | Bearer token from the token endpoint, requested with `client_secret_basic` (RFC 6749) | `tokenEndpoint`, `clientId`, `scopes` | the client secret |
| `OAUTH2_PRIVATE_KEY_JWT` | Bearer token from the token endpoint, requested with a signed `client_assertion` (RFC 7523 / SMART Backend Services) | `tokenEndpoint`, `clientId`, `keyId`, `jwksUrl`?, `scopes` | PKCS#8 PEM private key |
| `CDS_HOOKS_JWT` | A CDS Hooks 2.0 client JWT, signed per request | `clientId` (the `iss`), `keyId`, `jwksUrl`?, `tenant`? | PKCS#8 PEM private key |

OAuth2 tokens are cached in memory per (token endpoint, client ID, scopes)
until 30 seconds before `expires_in`; responses without `expires_in` aren't
cached. If the payer returns 401 on an OAuth2 connection, the cached token is
dropped and the request is retried exactly once with a fresh token.

### Signed JWTs

`CDS_HOOKS_JWT` and `OAUTH2_PRIVATE_KEY_JWT` both sign short-lived JWTs:
- **Lifetime and headers:** each JWT expires 5 minutes after issue, gets a
  fresh `jti`, and carries `kid` = `keyId` plus `jku` = `jwksUrl` when set.
- **CDS Hooks JWT claims:** `iss` = `clientId`; `aud` = the exact service URL
  being called (for example `https://payer/cds-services/order-sign-crd`);
  `tenant` is included when set.
- **Client assertion claims:** `iss` = `sub` = `clientId`; `aud` = the token
  endpoint.
- **Algorithm:** set by the key. RSA keys of 2048+ bits sign with RS384, and
  EC P-384 keys with ES384, the algorithms both specs recommend. Other curves
  and smaller RSA keys are rejected.

The payer needs your public key. Build a JWK Set and host it at `jwksUrl`,
or send it to the payer directly:

```java
String json = Jwks.builder()
        .add("key-2026-09", PemKeys.readPublicKey(publicKeyOrCertificatePem))
        .toJson();
```

To rotate keys, publish the old and new keys together. Then move `keyId` and
`credentialRef` to the new key, and drop the old key from the JWK Set once
nothing uses it.

Generate a P-384 key in the expected format with:

```sh
openssl ecparam -name secp384r1 -genkey -noout | openssl pkcs8 -topk8 -nocrypt -out signing-key.pem
openssl ec -in signing-key.pem -pubout -out signing-key.pub.pem
```

## Mutual TLS

Set `mtlsCredentialRef` on a record to connect with a client certificate. The
secret it resolves to is a PEM bundle: the certificate chain (leaf first)
followed by the PKCS#8 private key. The SDK builds one `HttpClient` per client
certificate and restricts it to TLS 1.2 and 1.3. Calls to the OAuth2 token
endpoint use that same client. If the certificate is rotated, a new client is
built automatically.

To trust a sandbox's private CA, pass a trust store:
`new CdsHooksClient(httpClient, credentials, trustStore)`. Connections without
mutual TLS use the `HttpClient` you pass in, so set its `SSLContext` yourself
if those also need a custom trust store.

Beyond that single 401 retry there are no retries or backoff, and no
connection pooling tuning. This is still a v1 client meant to show the flow
works, not a hardened production SDK.
