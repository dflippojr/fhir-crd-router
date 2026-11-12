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
 *       when something in it changed. A non-JSON response body has the raw and JSON-escaped spellings
 *       replaced, and is null if a loose JSON decoding of the rest still shows the token. A copy that is
 *       transformed (base64-encoded or split up, say) is not found. If the HOOK request body cannot be
 *       read as JSON, both bodies are null and the response headers are empty. The rest of a HOOK
 *       exchange is as sent or received.</li>
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
