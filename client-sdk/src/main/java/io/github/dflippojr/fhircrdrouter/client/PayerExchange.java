package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalInt;

/**
 * Immutable snapshot of one HTTP attempt, with credentials redacted. Exactly these are redacted:
 * <ul>
 *   <li>request {@code Authorization} header values become their scheme plus {@code [REDACTED]};
 *       response {@code Set-Cookie} headers are dropped;</li>
 *   <li>TOKEN requests have a null body, and TOKEN responses keep only scalar {@code token_type},
 *       {@code expires_in} and {@code scope};</li>
 *   <li>in a HOOK request body, {@code fhirAuthorization.access_token}, the EHR's FHIR token, becomes
 *       {@code [REDACTED]} (#164). The token is also replaced wherever else it appears: in every string
 *       value and key of a JSON request or response body, compared after JSON decoding, so no escape
 *       spelling hides it, and in every response header name and value. A JSON body is re-serialised only
 *       when something in it changed, and is null if its re-serialised text would still contain the token. A
 *       non-JSON response body has the raw and JSON-escaped spellings replaced, and is null if a loose JSON
 *       decoding of the rest still shows the token. A copy that is transformed (base64-encoded or split up,
 *       say) is not found. If the HOOK request body cannot be read as JSON, the request body is null;
 *       during a hook call the token is still known, so the rest is redacted as usual, and only when the
 *       token is unknown too are both bodies null, the response headers empty and {@code error}, if any,
 *       reduced to its kind. A response body counts as
 *       JSON only if all of it is one JSON value with no repeated key. When the token is known, a transport
 *       {@code error} is always a fresh exception of the same kind, its message naming the original class
 *       with the token removed, and no cause. The rest of a HOOK exchange is as sent or
 *       received.</li>
 *   <li>during a hook call, every exchange of every phase (HOOK, and TOKEN including a refresh after a
 *       401) has that token removed from its headers, bodies and error, after the TOKEN rules above; an
 *       exchange that would still show it is not delivered.</li>
 * </ul>
 * Discovery bodies are as sent or received. Missing responses have null responseBody and empty
 * headers/status. Nothing else is redacted: hook bodies may contain PHI, and the listener owns their
 * storage, disclosure and retention.
 */
public record PayerExchange(
        PayerCallPhase phase, String payerId, Environment environment,
        String method, URI uri, int attempt, Instant startedAt, Duration elapsed,
        OptionalInt statusCode, HttpHeaders requestHeaders, HttpHeaders responseHeaders,
        String requestBody, String responseBody, Exception error) {
}
