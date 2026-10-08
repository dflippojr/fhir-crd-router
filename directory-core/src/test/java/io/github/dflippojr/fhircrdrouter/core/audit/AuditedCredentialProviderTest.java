package io.github.dflippojr.fhircrdrouter.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class AuditedCredentialProviderTest {

    private static final AuditContext CONTEXT = new AuditContext(AuditContext.ActorKind.CLIENT, "client-1",
            null, AuditContext.Source.API, UUID.randomUUID());

    private final List<String> recorded = new ArrayList<>();
    private final AuditSink sink = (c, a, k, t, env, o, f) -> {
        recorded.add(a + ":" + o + ":" + t);
        return null;
    };

    private static AuditPersistenceException persistence(AuditContext c, String a, AuditEvent.Outcome o) {
        return new AuditPersistenceException(
                new AuditEvent(1, UUID.randomUUID(), Instant.now(), c, a, "credential", "x", null, o, List.of()));
    }

    /** Plain provider: only the base interface, scripted behaviour. */
    private static class Plain implements CredentialProvider {
        RuntimeException failure;
        Optional<String> value = Optional.of("sentinel-value");

        @Override public Optional<String> resolve(String ref) {
            if (failure != null) throw failure;
            return value;
        }

        @Override public void put(String ref, String secret) {
            if (failure != null) throw failure;
        }

        @Override public void remove(String ref) {
            if (failure != null) throw failure;
        }
    }

    private static final class Contextual extends Plain implements ContextualCredentialProvider {
        final List<AuditContext> seen = new ArrayList<>();

        @Override public Optional<String> resolve(AuditContext c, String ref) {
            seen.add(c);
            return resolve(ref);
        }

        @Override public void put(AuditContext c, String ref, String secret) {
            seen.add(c);
            put(ref, secret);
        }

        @Override public void remove(AuditContext c, String ref) {
            seen.add(c);
            remove(ref);
        }
    }

    @Test
    void plainDelegateEventsAndUnknownContextOverloads() {
        var provider = new AuditedCredentialProvider(new Plain(), sink);
        provider.put("ref-1", "sentinel-value");
        assertTrue(provider.resolve("ref-1").isPresent());
        provider.remove("ref-1");
        assertEquals(List.of("credential.put:ATTEMPTED:ref-1", "credential.put:SUCCEEDED:ref-1",
                "credential.resolve.found:SUCCEEDED:ref-1", "credential.remove:ATTEMPTED:ref-1",
                "credential.remove:SUCCEEDED:ref-1"), recorded);
        assertFalse(recorded.toString().contains("sentinel"));
    }

    @Test
    void contextualDelegateReceivesTheCallersContext() {
        var delegate = new Contextual();
        var provider = new AuditedCredentialProvider(delegate, sink);
        provider.put(CONTEXT, "ref-1", "v");
        provider.resolve(CONTEXT, "ref-1");
        provider.remove(CONTEXT, "ref-1");
        assertEquals(3, delegate.seen.size());
        delegate.seen.forEach(c -> assertSame(CONTEXT, c));
    }

    @Test
    void notFoundAndFailureReasonCodes() {
        var delegate = new Plain();
        var provider = new AuditedCredentialProvider(delegate, sink);
        delegate.value = Optional.empty();
        assertTrue(provider.resolve(CONTEXT, "ref-1").isEmpty());
        delegate.failure = new UncheckedIOException(new IOException("C:\\private\\path"));
        assertThrows(UncheckedIOException.class, () -> provider.resolve(CONTEXT, "ref-1"));
        delegate.failure = new IllegalStateException("secret-bearing message");
        assertThrows(IllegalStateException.class, () -> provider.resolve(CONTEXT, "ref-1"));
        assertEquals(List.of("credential.resolve.not_found:SUCCEEDED:ref-1",
                "credential.resolve.failed.io_error:FAILED:ref-1",
                "credential.resolve.failed.provider_error:FAILED:ref-1"), recorded);
        assertFalse(recorded.toString().contains("private"));
    }

    @Test
    void mutationFailureIsFailedAndKeepsOriginalExceptionWhenAuditAlsoFails() {
        var delegate = new Plain();
        delegate.failure = new IllegalStateException("write failed");
        AuditSink failsOnFailed = (c, a, k, t, env, o, f) -> {
            if (o == AuditEvent.Outcome.FAILED) throw persistence(c, a, o);
            recorded.add(a + ":" + o);
            return null;
        };
        var provider = new AuditedCredentialProvider(delegate, failsOnFailed);
        var thrown = assertThrows(IllegalStateException.class, () -> provider.put(CONTEXT, "ref-1", "v"));
        assertEquals(1, thrown.getSuppressed().length);
        assertEquals(List.of("credential.put:ATTEMPTED"), recorded);

        delegate.failure = new IllegalStateException("read failed"); // fresh instance: suppressed is per exception
        var resolveThrown = assertThrows(IllegalStateException.class, () -> provider.resolve(CONTEXT, "ref-1"));
        assertEquals(1, resolveThrown.getSuppressed().length);
    }

    @Test
    void auditExceptionFromDelegatePropagatesUnchanged() {
        var delegate = new Plain();
        delegate.failure = persistence(CONTEXT, "credential.key.create", AuditEvent.Outcome.ATTEMPTED);
        var provider = new AuditedCredentialProvider(delegate, sink);
        assertSame(delegate.failure, assertThrows(AuditPersistenceException.class,
                () -> provider.put(CONTEXT, "ref-1", "v")));
        assertSame(delegate.failure, assertThrows(AuditPersistenceException.class,
                () -> provider.resolve(CONTEXT, "ref-1")));
        assertEquals(List.of("credential.put:ATTEMPTED:ref-1"), recorded);
    }

    @Test
    void targetsAreOpaque() {
        assertEquals("ref-1", AuditTargets.opaque("ref-1"));
        String hashed = AuditTargets.opaque("-----BEGIN PEM-----");
        assertTrue(hashed.startsWith("ref-"));
        assertFalse(hashed.contains("PEM"));
        assertEquals(hashed, AuditTargets.opaque("-----BEGIN PEM-----"));
        assertTrue(AuditTargets.opaque(null).startsWith("ref-"));
        assertEquals(Environment.SANDBOX, Environment.valueOf("SANDBOX"));
    }
}
