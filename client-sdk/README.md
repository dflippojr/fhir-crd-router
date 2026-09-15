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

Auth is derived from `record.authType()`:

| authType | Behavior |
| --- | --- |
| `NONE` | No auth header. |
| `API_KEY` | `Authorization: Bearer <resolved credentialRef>`. |
| `OAUTH2_CLIENT_CREDENTIALS` | Fetches a token from `record.tokenEndpoint()` using `record.clientId()` plus the client secret resolved from `credentialRef` (RFC 6749 `client_secret_basic`), then sends `Authorization: Bearer <token>`. |
| `MUTUAL_TLS` | Not implemented at the per-request level yet — needs an `HttpClient` built with the right `SSLContext`/client cert, which is a caller-side concern for now. |

OAuth2 tokens are cached in memory per (token endpoint, client ID, scopes)
until 30 seconds before `expires_in`; responses without `expires_in` aren't
cached. If the payer returns 401 on an OAuth2 connection, the cached token is
dropped and the request is retried exactly once with a fresh token.

Beyond that single 401 retry there are no retries or backoff, and no
connection pooling tuning. This is still a v1 client meant to show the flow
works, not a hardened production SDK.
