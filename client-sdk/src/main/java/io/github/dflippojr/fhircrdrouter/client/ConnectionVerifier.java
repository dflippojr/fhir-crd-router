package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CredentialLookup.CredentialReadException;
import io.github.dflippojr.fhircrdrouter.client.CredentialLookup.MissingCredentialException;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.io.IOException;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;
import java.util.function.Supplier;

/**
 * Turns one discovery exchange into the report {@link CdsHooksClient#verify} returns: the catalog it returned,
 * or the phase, status and reason of the failure that stopped it. A reason never quotes a response body, a
 * header, a credential or an exception message.
 */
final class ConnectionVerifier {
    private ConnectionVerifier() { }

    /** Runs {@code discovery}, the exchange for {@code record}, and reports the outcome. */
    static ConnectionVerification verify(ConnectionRecord record, ObjectMapper mapper,
                                         Supplier<HttpResponse<String>> discovery) {
        String payerId = record.payerId();
        Environment environment = record.environment();
        Instant checkedAt = Instant.now();
        long started = System.nanoTime();
        try {
            HttpResponse<String> response = discovery.get();
            JsonNode catalog;
            try {
                catalog = mapper.readTree(response.body());
            } catch (IOException e) {
                return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                        PayerCallPhase.DISCOVERY, OptionalInt.of(response.statusCode()),
                        "discovery response is not valid JSON");
            }
            JsonNode services = catalog == null ? null : catalog.get("services");
            List<String> hooks = new ArrayList<>();
            int serviceCount = 0;
            if (services != null && services.isArray()) {
                serviceCount = services.size();
                for (JsonNode service : services) {
                    JsonNode hook = service.get("hook");
                    if (hook != null && hook.isTextual() && !hook.textValue().isBlank()) {
                        hooks.add(hook.textValue());
                    }
                }
            }
            return ConnectionVerification.catalog(payerId, environment, checkedAt, since(started),
                    hooks, serviceCount, CdsDiscoveryValidator.validate(catalog));
        } catch (PayerCallException e) {
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    e.phase(), e.statusCode(), payerCallReason(e));
        } catch (MissingCredentialException e) {
            PayerCallPhase phase = e.phaseOrDiscovery();
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "missing credential for " + describe(phase));
        } catch (CredentialReadException e) {
            PayerCallPhase phase = e.phaseOrDiscovery();
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "credential could not be read: "
                            + e.getCause().getClass().getSimpleName());
        } catch (EndpointUrlException e) {
            // No exchange was attempted, so no phase; the problem text never includes the URL.
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    null, OptionalInt.empty(), e.field() + " " + e.problem());
        } catch (RouterException | IllegalArgumentException e) {
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    null, OptionalInt.empty(), "connection could not be verified: " + e.getClass().getSimpleName());
        }
    }

    private static String payerCallReason(PayerCallException e) {
        String request = describe(e.phase());
        if (e.statusCode().isPresent()) {
            return request + " returned HTTP " + e.statusCode().getAsInt();
        }
        return request + (e.timedOut() ? " timed out" : " transport failure");
    }

    private static String describe(PayerCallPhase phase) {
        return switch (phase) {
            case DISCOVERY -> "discovery request";
            case TOKEN -> "token request";
            case HOOK -> "hook request";
        };
    }

    private static Duration since(long startedNanos) {
        return Duration.ofNanos(Math.max(0, System.nanoTime() - startedNanos));
    }
}
