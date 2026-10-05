package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpTimeoutException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.OptionalInt;
import java.util.Set;

/** A failed payer exchange, with bounded diagnostics and an allowlist of response headers. */
public final class PayerCallException extends RouterException {
    private static final int BODY_LIMIT = 4096;
    private static final Set<String> ALLOWED_HEADERS = Set.of(
            "www-authenticate", "retry-after", "content-type", "x-request-id", "x-correlation-id");

    private final PayerCallPhase phase;
    private final String payerId;
    private final URI uri;
    private final OptionalInt statusCode;
    private final HttpHeaders responseHeaders;
    private final String responseBody;

    /** The body must already be sanitized for TOKEN errors; never supply a successful token body. */
    public PayerCallException(String messagePrefix, PayerCallPhase phase, String payerId, URI uri,
                              HttpResponse<String> response, String body) {
        this(messagePrefix, phase, payerId, uri, response, body, null);
    }

    private PayerCallException(String messagePrefix, PayerCallPhase phase, String payerId, URI uri,
                               HttpResponse<String> response, String body, Throwable cause) {
        super(messagePrefix + truncate(body), cause);
        this.phase = phase;
        this.payerId = payerId;
        this.uri = uri;
        this.statusCode = response == null ? OptionalInt.empty() : OptionalInt.of(response.statusCode());
        this.responseHeaders = HttpHeaders.of(response == null ? Map.of() : response.headers().map(),
                (name, value) -> ALLOWED_HEADERS.contains(name.toLowerCase(Locale.ROOT)));
        this.responseBody = truncate(body);
    }

    public static PayerCallException transport(String message, PayerCallPhase phase, String payerId,
                                               URI uri, Throwable cause) {
        return new PayerCallException(message, phase, payerId, uri, null, "", cause);
    }

    public PayerCallPhase phase() { return phase; }
    public String payerId() { return payerId; }
    public URI uri() { return uri; }
    public OptionalInt statusCode() { return statusCode; }
    public HttpHeaders responseHeaders() { return responseHeaders; }
    public String responseBody() { return responseBody; }
    public boolean timedOut() { return getCause() instanceof HttpTimeoutException; }

    private static String truncate(String body) {
        if (body == null) {
            return "";
        }
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        if (bytes.length <= BODY_LIMIT) {
            return body;
        }
        int end = BODY_LIMIT;
        while ((bytes[end] & 0xc0) == 0x80) {
            end--;
        }
        return new String(bytes, 0, end, StandardCharsets.UTF_8);
    }
}
