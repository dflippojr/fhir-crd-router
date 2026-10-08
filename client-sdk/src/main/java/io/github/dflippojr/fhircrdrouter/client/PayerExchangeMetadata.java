package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.OptionalInt;

/**
 * Immutable, allowlisted projection of one HTTP attempt for audit logging. It holds no
 * reference to the originating {@link PayerExchange}, and never carries URIs, bodies,
 * headers, exceptions or messages. {@code payerId} is the configured opaque payer-directory
 * identifier and must be non-sensitive; this projection cannot sanitize a misconfigured one.
 *
 * <p>{@link Outcome} describes the HTTP attempt only. It does not claim that JSON parsing,
 * validation or any clinical action succeeded. No initiating actor, logical-call correlation,
 * retention or integrity guarantee is supplied; hosts must provide that context.
 */
public record PayerExchangeMetadata(
        PayerCallPhase phase, String payerId, Environment environment, String method,
        int attempt, Instant startedAt, Duration elapsed, OptionalInt statusCode, Outcome outcome) {

    /** Fixed result categories of one HTTP attempt. */
    public enum Outcome { HTTP_SUCCESS, HTTP_ERROR, TIMEOUT, INTERRUPTED, TRANSPORT_ERROR }

    public PayerExchangeMetadata {
        Objects.requireNonNull(phase, "phase");
        Objects.requireNonNull(payerId, "payerId");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(startedAt, "startedAt");
        Objects.requireNonNull(elapsed, "elapsed");
        Objects.requireNonNull(statusCode, "statusCode");
        Objects.requireNonNull(outcome, "outcome");
    }

    /** Projects only the allowlisted fields; a status, when present, determines the HTTP outcome. */
    public static PayerExchangeMetadata from(PayerExchange exchange) {
        Objects.requireNonNull(exchange, "exchange");
        return new PayerExchangeMetadata(exchange.phase(), exchange.payerId(), exchange.environment(),
                exchange.method(), exchange.attempt(), exchange.startedAt(), exchange.elapsed(),
                exchange.statusCode(), outcome(exchange));
    }

    private static Outcome outcome(PayerExchange exchange) {
        if (exchange.statusCode().isPresent()) {
            int status = exchange.statusCode().getAsInt();
            return status >= 200 && status < 300 ? Outcome.HTTP_SUCCESS : Outcome.HTTP_ERROR;
        }
        Exception error = exchange.error();
        if (error instanceof HttpTimeoutException) {
            return Outcome.TIMEOUT;
        }
        return error instanceof InterruptedException ? Outcome.INTERRUPTED : Outcome.TRANSPORT_ERROR;
    }
}
