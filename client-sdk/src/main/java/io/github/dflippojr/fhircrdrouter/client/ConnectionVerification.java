package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.core.Environment;

import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.SortedSet;
import java.util.TreeSet;

/**
 * The outcome of {@link CdsHooksClient#verify}: whether a connection's discovery endpoint
 * answered 2xx with a catalog that passes {@link CdsDiscoveryValidator}, and what it offers.
 * Holds no response bodies, headers or credential material.
 *
 * @param ok true only when discovery succeeded, parsed and produced no findings
 * @param hooks advertised hook names, sorted and deduplicated
 * @param serviceCount entries in the catalog's {@code services} array
 * @param findings validator findings for a catalog that was fetched and parsed
 * @param failurePhase the exchange that failed, when one did and it is known
 * @param failureStatus the payer's HTTP status for that failure, when it answered
 * @param failureReason short text built from the failure type, phase and status; empty when ok
 */
public record ConnectionVerification(
        String payerId,
        Environment environment,
        Instant checkedAt,
        Duration elapsed,
        boolean ok,
        SortedSet<String> hooks,
        int serviceCount,
        List<CdsDiscoveryValidator.Violation> findings,
        Optional<PayerCallPhase> failurePhase,
        OptionalInt failureStatus,
        String failureReason
) {
    public ConnectionVerification {
        Objects.requireNonNull(payerId, "payerId");
        Objects.requireNonNull(environment, "environment");
        Objects.requireNonNull(checkedAt, "checkedAt");
        Objects.requireNonNull(elapsed, "elapsed");
        hooks = Collections.unmodifiableSortedSet(new TreeSet<>(Objects.requireNonNull(hooks, "hooks")));
        findings = List.copyOf(findings);
        Objects.requireNonNull(failurePhase, "failurePhase");
        Objects.requireNonNull(failureStatus, "failureStatus");
        Objects.requireNonNull(failureReason, "failureReason");
        if (serviceCount < 0) {
            throw new IllegalArgumentException("serviceCount must not be negative");
        }
        if (ok && (!findings.isEmpty() || failurePhase.isPresent() || failureStatus.isPresent()
                || !failureReason.isEmpty())) {
            throw new IllegalArgumentException("a successful verification has no findings or failure");
        }
    }

    static ConnectionVerification catalog(String payerId, Environment environment, Instant checkedAt,
                                          Duration elapsed, Collection<String> hooks, int serviceCount,
                                          List<CdsDiscoveryValidator.Violation> findings) {
        boolean ok = findings.isEmpty();
        return new ConnectionVerification(payerId, environment, checkedAt, elapsed, ok, new TreeSet<>(hooks),
                serviceCount, findings, Optional.empty(), OptionalInt.empty(),
                ok ? "" : "discovery catalog has " + findings.size() + " finding(s)");
    }

    static ConnectionVerification failure(String payerId, Environment environment, Instant checkedAt,
                                          Duration elapsed, PayerCallPhase phase, OptionalInt status,
                                          String reason) {
        return new ConnectionVerification(payerId, environment, checkedAt, elapsed, false, new TreeSet<>(), 0,
                List.of(), Optional.ofNullable(phase), status, reason);
    }
}
