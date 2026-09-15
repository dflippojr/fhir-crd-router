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
| `OAUTH2_CLIENT_CREDENTIALS` | Fetches a token from `record.tokenEndpoint()` using `record.clientId()` plus the client secret resolved from `credentialRef` (RFC 6749 `client_secret_basic`), then sends `Authorization: Bearer <token>`. |
| `MUTUAL_TLS` | Not implemented at the per-request level yet — needs an `HttpClient` built with the right `SSLContext`/client cert, which is a caller-side concern for now. |

OAuth2 tokens are cached in memory per (token endpoint, client ID, scopes)
until 30 seconds before `expires_in`; responses without `expires_in` aren't
cached. If the payer returns 401 on an OAuth2 connection, the cached token is
dropped and the request is retried exactly once with a fresh token.

Beyond that single 401 retry there are no retries or backoff, and no
connection pooling tuning. This is still a v1 client meant to show the flow
works, not a hardened production SDK.
