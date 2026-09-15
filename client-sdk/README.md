# client-sdk

Given a resolved `ConnectionRecord` (from `PayerRouter.resolve(...)`), calls
the payer directly — the router itself never makes this call.

- `discoverServices(record)` — hits the payer's standard
  `GET {baseUrl}/cds-services` and returns the parsed service list. Nothing
  is cached or curated by the router; this always asks the payer live.
- `callHook(record, serviceId, request)` — typed response (`cards()` as
  `List<Card>`) plus `rawJson()` passthrough on the same `CdsHookResponse`.
- `callHookRaw(record, serviceId, request)` — raw `JsonNode` only.

Auth is derived from `record.authType()`:

| authType | Behavior |
| --- | --- |
| `NONE` | No auth header. |
| `API_KEY` | `Authorization: Bearer <resolved credentialRef>`. |
| `OAUTH2_CLIENT_CREDENTIALS` | Fetches a token from `record.tokenEndpoint()` first — see the important caveat in `OAuth2TokenClient`'s javadoc about how `clientId:clientSecret` is currently packed into `credentialRef`, since the locked schema doesn't have a separate `clientId` field yet. |
| `MUTUAL_TLS` | Not implemented at the per-request level yet — needs an `HttpClient` built with the right `SSLContext`/client cert, which is a caller-side concern for now. |

No retries, no token caching, no connection pooling tuning — this is a v1
"prove the flow works" client, not a hardened production SDK.
