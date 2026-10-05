package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.time.Duration;
import java.time.Instant;
import java.util.OptionalInt;

/**
 * Immutable snapshot of one HTTP attempt, with SDK authentication secrets redacted.
 * Bodies are strings as sent/received; TOKEN requests have a null body and TOKEN
 * responses contain only token_type, expires_in and scope. Missing responses have
 * null responseBody and empty headers/status. Hook bodies may contain PHI; the
 * listener owns their storage, disclosure and retention.
 */
public record PayerExchange(
        PayerCallPhase phase, String payerId, Environment environment,
        String method, URI uri, int attempt, Instant startedAt, Duration elapsed,
        OptionalInt statusCode, HttpHeaders requestHeaders, HttpHeaders responseHeaders,
        String requestBody, String responseBody, Exception error) {
}
