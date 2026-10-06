package io.github.dflippojr.fhircrdrouter.client;

import java.time.Duration;
import java.util.Objects;

/**
 * Opt-in bounded retry for payer throttling. Only 429 and 503 responses that carry a usable
 * {@code Retry-After} are retried, and only {@code Retry-After} decides how long to wait: there
 * is no guessed backoff. If the payer asks for more than the remaining {@code maxTotalWait}, the
 * call fails immediately with the {@link PayerCallException}. CDS Hooks calls are interactive,
 * so keep both limits small.
 *
 * @param maxAttempts total HTTP attempts per call, including the first; 1 disables retry
 * @param maxTotalWait the most time a single call may spend sleeping between attempts
 */
public record RetryPolicy(int maxAttempts, Duration maxTotalWait) {
    /** Retry disabled: the default. */
    public static final RetryPolicy NONE = new RetryPolicy(1, Duration.ZERO);

    public RetryPolicy {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be at least 1");
        }
        Objects.requireNonNull(maxTotalWait, "maxTotalWait");
        if (maxTotalWait.isNegative()) {
            throw new IllegalArgumentException("maxTotalWait must not be negative");
        }
    }

    boolean enabled() {
        return maxAttempts > 1;
    }

    static boolean retryable(int status) {
        return status == 429 || status == 503;
    }
}
