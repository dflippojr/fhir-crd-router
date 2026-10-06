package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.net.http.HttpTimeoutException;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
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

    /** True when the payer answered HTTP 429. */
    public boolean isRateLimited() { return statusCode.isPresent() && statusCode.getAsInt() == 429; }

    /**
     * The payer's {@code Retry-After} as a wait, from delta-seconds or an HTTP-date (RFC 9110).
     * A date in the past yields {@link Duration#ZERO}; a missing or unparseable value yields empty.
     */
    public Optional<Duration> retryAfter() {
        return retryAfter(Clock.systemUTC());
    }

    Optional<Duration> retryAfter(Clock clock) {
        return responseHeaders.firstValue("Retry-After").flatMap(v -> parseRetryAfter(v, clock));
    }

    static Optional<Duration> parseRetryAfter(String value, Clock clock) {
        String v = value.strip();
        if (v.isEmpty()) {
            return Optional.empty();
        }
        if (v.chars().allMatch(c -> c >= '0' && c <= '9')) {
            try {
                return Optional.of(Duration.ofSeconds(Long.parseLong(v)));
            } catch (NumberFormatException e) {
                return Optional.empty();
            }
        }
        try {
            ZonedDateTime date = ZonedDateTime.parse(v, DateTimeFormatter.RFC_1123_DATE_TIME);
            Duration wait = Duration.between(clock.instant(), date.toInstant());
            return Optional.of(wait.isNegative() ? Duration.ZERO : wait);
        } catch (DateTimeException e) {
            return Optional.empty();
        }
    }

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
