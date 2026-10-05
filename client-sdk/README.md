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

### Validating coverage information

Parsing is lenient on purpose. To tell a payer what is wrong with a
determination, check it against the CRD 2.2.1 `ext-coverage-information`
profile:

```java
for (CoverageInformation info : response.coverageInformation()) {
    for (CoverageInformationValidator.Violation v : CoverageInformationValidator.validate(info)) {
        System.out.printf("%s %s: %s%n", v.severity(), v.path(), v.message());
        // ERROR extension[date]: date is required
    }
}
```

`validate(JsonNode)` takes the raw extension object instead. Each `Violation`
has a `severity` (`ERROR` or `WARNING`), a `path` such as
`extension[coverage-assertion-id]`, and a plain-language `message`. The rules
are hand-written from the published StructureDefinition (no FHIR validator
dependency): required sub-extensions and their cardinality, value types, the
required code bindings for `covered`, `pa-needed`, `doc-needed`, `doc-purpose`
and `info-needed`, the FHIR `date` format, a `coverage` reference to a
Coverage, and invariants `crd-ci-q1` to `crd-ci-q9` (cited in the message).
Unknown sub-extensions are allowed, since the profile's slicing is open, and
the internals of `detail` are not checked.

The pre-2.x `identifier` sub-extension in place of `coverage-assertion-id` is
a `WARNING`, not an `ERROR`. The reference implementation's responses also
get `ERROR`s for missing `covered` and `date`, which 2.2.1 requires.

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

## Payer call errors and timeouts

Discovery, token and hook HTTP failures throw `PayerCallException`, a subclass
of `RouterException`, so existing catch blocks still work. `phase()` returns
`PayerCallPhase.DISCOVERY`, `TOKEN` or `HOOK`; `payerId()` and `uri()` identify
the call. `statusCode()` is an `OptionalInt`, empty for transport failures,
interruptions and timeouts. `timedOut()` distinguishes HTTP request/connect
timeouts from other transport errors; the cause preserves the transport error.

`responseHeaders()` returns immutable, case-insensitive Java `HttpHeaders`
containing only `WWW-Authenticate`, `Retry-After`, `Content-Type`, `X-Request-Id`
and `X-Correlation-Id`. `responseBody()` and the body included in the message
are limited to 4096 UTF-8 bytes, without splitting a character. Token error
bodies include only textual RFC 6749 `error` and `error_description` fields,
with an echoed credential redacted; non-JSON token errors become `{}`.
Successful token bodies are never attached to exceptions. Hook and discovery
bodies may contain sensitive clinical data; take care when logging them.

```java
try {
    client.discoverServices(record);
} catch (PayerCallException e) {
    e.phase();
    e.statusCode();
    e.responseHeaders().firstValue("Retry-After");
    e.timedOut();
}
```

Existing constructors use a **10-second timeout per request**, including token
requests and the OAuth2 401 retry. SDK-built clients (including mutual TLS)
use a **5-second connect timeout**. These are per-exchange budgets, so a token
fetch and a retried hook can take multiple request budgets in total.

```java
CdsHooksClient client = new CdsHooksClient(credentials,
        Duration.ofSeconds(3),   // request timeout
        Duration.ofSeconds(2)); // connect timeout

// With a custom HTTP client and optional mTLS trust store:
CdsHooksClient custom = new CdsHooksClient(httpClient, credentials, trustStore,
        Duration.ofSeconds(3), Duration.ofSeconds(2));
```

Both durations must be positive. A supplied `HttpClient` keeps its own connect
timeout; set it on that client's builder. The custom constructor's connect
timeout applies to SDK-built mutual TLS clients. Standalone `OAuth2TokenClient`
users can pass `(httpClient, requestTimeout)`; its existing constructor defaults
to 10 seconds. No retry is added for 429 or 5xx responses.


## Exchange logging and tracing

Register a `PayerExchangeListener` through the timeout constructor. Existing
constructors default to a no-op and need no changes:

```java
CdsHooksClient client = new CdsHooksClient(credentials,
        Duration.ofSeconds(3), Duration.ofSeconds(2),
        exchange -> System.out.printf("%s %s %s status=%s %d ms%n",
                exchange.phase(), exchange.method(), exchange.uri(),
                exchange.statusCode().isPresent() ? exchange.statusCode().getAsInt() : "transport-error",
                exchange.elapsed().toMillis()));

// Also available with a custom client and optional mTLS trust store:
CdsHooksClient custom = new CdsHooksClient(httpClient, credentials, trustStore,
        Duration.ofSeconds(3), Duration.ofSeconds(2), listener);
```

Each immutable `PayerExchange` identifies the `PayerCallPhase`, payer, environment,
HTTP method, URI and attempt, with an `Instant startedAt` and monotonic `Duration
elapsed` measuring the HTTP send (excluding authentication and listener execution).
Headers are immutable, case-insensitive `HttpHeaders`; bodies are strings.
`statusCode` is an `OptionalInt`; transport failures, interruptions and timeouts
have no status or response body, empty response headers and the original exception
in `error`. HTTP error responses have a status and body with no transport error.
Exchanges are delivered before parsing, including failed or malformed responses.

OAuth2's 401 retry reports TOKEN 1, HOOK 401 attempt 1, TOKEN 2, HOOK attempt 2
when a fresh token is required initially. Cached tokens produce no HTTP exchange.
Discovery retries use the same attempt numbering. Callbacks run synchronously in
send order; exceptions from the listener are ignored. Keep callbacks brief, and
make listeners thread safe if you share the SDK client across threads. No logging,
metrics or tracing framework dependency is required.

Before delivery, the SDK replaces Authorization values with their scheme plus
`[REDACTED]` and drops Set-Cookie headers. TOKEN request bodies are omitted (`null`),
and TOKEN response bodies become JSON containing only scalar `token_type`,
`expires_in` and `scope` fields; malformed or non-JSON responses become `{}`.
These rules also apply to unsuccessful token requests.

**PHI:** HOOK request and response bodies pass through exactly as sent and received.
They may contain protected health information (PHI), including any FHIR authorization
supplied in a hook request. The listener owns what it logs, traces, stores and retains;
apply your deployment's access and retention controls. Discovery bodies also pass
through. The quickstart prints metadata only, one line per HTTP exchange.
