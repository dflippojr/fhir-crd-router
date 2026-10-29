package io.github.dflippojr.fhircrdrouter.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Golden sink calls for the ATTEMPTED -> mutation -> SUCCEEDED/FAILED sequence of both audit wrappers
 * (#172). The sink arguments are everything a wrapper contributes to an audit line (the trail adds
 * eventId, occurredAt and sha256, pinned by {@link AuditJsonGoldenTest}), so pinning them pins the bytes.
 * Recorded on master before the shared sequence was extracted.
 */
class AuditedMutationSequenceTest {

    private static final AuditContext CONTEXT = new AuditContext(AuditContext.ActorKind.CLIENT, "client-1",
            "delegator-1", AuditContext.Source.CLI, UUID.fromString("00000000-0000-4000-8000-000000000003"));

    private static final String CREATED_FIELDS = "[displayName, baseUrl, authType, status, contactInfo]";
    private static final String CREATE_ATTEMPTED =
            "connection.create|connection|synthetic-payer|SANDBOX|ATTEMPTED|" + CREATED_FIELDS;

    private final List<String> calls = new ArrayList<>();
    private AuditEvent.Outcome failOn;

    /** Every call, including the ones it fails, must carry the caller's context instance. */
    private final AuditSink sink = (c, a, k, t, env, o, f) -> {
        assertSame(CONTEXT, c);
        if (o == failOn) {
            throw new AuditPersistenceException(new AuditEvent(1, UUID.randomUUID(), Instant.EPOCH, c, a, k, t,
                    env, o, f));
        }
        calls.add(a + "|" + k + "|" + t + "|" + env + "|" + o + "|" + f);
        return null;
    };

    private static AuditPersistenceException delegateAuditFailure() {
        return new AuditPersistenceException(new AuditEvent(1, UUID.randomUUID(), Instant.EPOCH, CONTEXT,
                "credential.key.create", "credential", "key-1", null, AuditEvent.Outcome.ATTEMPTED, List.of()));
    }

    private static ConnectionRecord.Builder record() {
        return ConnectionRecord.builder().payerId("synthetic-payer").environment(Environment.SANDBOX)
                .displayName("Synthetic").baseUrl("https://payer.example.invalid/fhir").authType(AuthType.NONE)
                .contactInfo("ops@example.invalid");
    }

    /** In-memory store that throws {@link #failure} from save and delete when set. */
    private static final class MemoryStore implements ConnectionStore {
        ConnectionRecord stored;
        Throwable failure;

        private void maybeFail() {
            if (failure instanceof RuntimeException e) throw e;
            if (failure instanceof Error e) throw e;
        }

        @Override public List<ConnectionRecord> findByPayerId(String payerId) {
            return stored == null ? List.of() : List.of(stored);
        }

        @Override public Optional<ConnectionRecord> findByPayerIdAndEnvironment(String payerId, Environment env) {
            return Optional.ofNullable(stored);
        }

        @Override public List<ConnectionRecord> findAll() {
            return findByPayerId(null);
        }

        @Override public void save(ConnectionRecord record) {
            maybeFail();
            stored = record;
        }

        @Override public void delete(String payerId, Environment environment) {
            maybeFail();
            stored = null;
        }
    }

    /** Contextual provider that throws {@link #failure} from put and remove when set. */
    private static final class Provider implements ContextualCredentialProvider {
        final List<String> delegated = new ArrayList<>();
        Throwable failure;

        private void call(String what) {
            delegated.add(what);
            if (failure instanceof RuntimeException e) throw e;
            if (failure instanceof Error e) throw e;
        }

        @Override public Optional<String> resolve(String ref) { return Optional.empty(); }
        @Override public void put(String ref, String secret) { call("put"); }
        @Override public void remove(String ref) { call("remove"); }
        @Override public Optional<String> resolve(AuditContext c, String ref) { return Optional.empty(); }
        @Override public void put(AuditContext c, String ref, String secret) { call("put(context)"); }
        @Override public void remove(AuditContext c, String ref) { call("remove(context)"); }
    }

    @Test
    void storeSuccessfulMutationsRecordAttemptedThenSucceeded() {
        var store = new AuditedConnectionStore(new MemoryStore(), sink);
        store.save(CONTEXT, record().build());
        store.save(CONTEXT, record().status(ConnectionStatus.INACTIVE).scopes(List.of("system/*.read")).build());
        store.save(CONTEXT, record().status(ConnectionStatus.INACTIVE).scopes(List.of("system/*.read")).build());
        store.delete(CONTEXT, "synthetic-payer", Environment.SANDBOX);
        store.delete(CONTEXT, "synthetic-payer", Environment.SANDBOX);
        store.save(CONTEXT, record().payerId("payer with spaces").build());
        assertEquals(List.of(
                CREATE_ATTEMPTED,
                CREATE_ATTEMPTED.replace("ATTEMPTED", "SUCCEEDED"),
                "connection.update|connection|synthetic-payer|SANDBOX|ATTEMPTED|[scopes, status]",
                "connection.update|connection|synthetic-payer|SANDBOX|SUCCEEDED|[scopes, status]",
                "connection.no_change|connection|synthetic-payer|SANDBOX|ATTEMPTED|[]",
                "connection.no_change|connection|synthetic-payer|SANDBOX|SUCCEEDED|[]",
                "connection.delete|connection|synthetic-payer|SANDBOX|ATTEMPTED|[]",
                "connection.delete|connection|synthetic-payer|SANDBOX|SUCCEEDED|[]",
                "connection.delete_missing|connection|synthetic-payer|SANDBOX|ATTEMPTED|[]",
                "connection.delete_missing|connection|synthetic-payer|SANDBOX|SUCCEEDED|[]",
                "connection.create|connection|" + AuditTargets.opaque("payer with spaces")
                        + "|SANDBOX|ATTEMPTED|" + CREATED_FIELDS,
                "connection.create|connection|" + AuditTargets.opaque("payer with spaces")
                        + "|SANDBOX|SUCCEEDED|" + CREATED_FIELDS), calls);
    }

    @Test
    void storeDelegateFailureRecordsFailedAndRethrowsTheSameInstance() {
        var delegate = new MemoryStore();
        var store = new AuditedConnectionStore(delegate, sink);
        var runtime = new IllegalStateException("boom");
        delegate.failure = runtime;
        assertSame(runtime, assertThrows(IllegalStateException.class, () -> store.save(CONTEXT, record().build())));
        var error = new AssertionError("fatal");
        delegate.failure = error;
        assertSame(error, assertThrows(AssertionError.class,
                () -> store.delete(CONTEXT, "synthetic-payer", Environment.PRODUCTION)));
        assertEquals(0, runtime.getSuppressed().length);
        assertEquals(0, error.getSuppressed().length);
        assertEquals(List.of(
                CREATE_ATTEMPTED,
                CREATE_ATTEMPTED.replace("ATTEMPTED", "FAILED"),
                "connection.delete_missing|connection|synthetic-payer|PRODUCTION|ATTEMPTED|[]",
                "connection.delete_missing|connection|synthetic-payer|PRODUCTION|FAILED|[]"), calls);
    }

    @Test
    void storeFailedRecordThatFailsIsSuppressedOnTheOriginal() {
        var delegate = new MemoryStore();
        var store = new AuditedConnectionStore(delegate, sink);
        var runtime = new IllegalStateException("boom");
        delegate.failure = runtime;
        failOn = AuditEvent.Outcome.FAILED;
        assertSame(runtime, assertThrows(IllegalStateException.class, () -> store.save(CONTEXT, record().build())));
        assertEquals(1, runtime.getSuppressed().length);
        var suppressed = (AuditPersistenceException) runtime.getSuppressed()[0];
        assertEquals(AuditPersistenceException.OperationState.COMPLETED_ACTION_AUDIT_FAILED,
                suppressed.operationState());
        assertEquals(List.of(CREATE_ATTEMPTED), calls);
    }

    /** Store wrapper: an audit failure thrown by the delegate is itself audited as FAILED (#172, option a). */
    @Test
    void storeDelegateAuditFailureIsRecordedAsFailed() {
        var delegate = new MemoryStore();
        var store = new AuditedConnectionStore(delegate, sink);
        var fromDelegate = delegateAuditFailure();
        delegate.failure = fromDelegate;
        assertSame(fromDelegate, assertThrows(AuditPersistenceException.class,
                () -> store.save(CONTEXT, record().build())));
        assertEquals(0, fromDelegate.getSuppressed().length);
        assertEquals(List.of(
                CREATE_ATTEMPTED,
                CREATE_ATTEMPTED.replace("ATTEMPTED", "FAILED")),
                calls);

        var second = delegateAuditFailure();
        delegate.failure = second;
        failOn = AuditEvent.Outcome.FAILED;
        assertSame(second, assertThrows(AuditPersistenceException.class,
                () -> store.delete(CONTEXT, "synthetic-payer", Environment.SANDBOX)));
        assertEquals(1, second.getSuppressed().length);
    }

    @Test
    void storeAttemptNotRecordedNeverCallsTheDelegate() {
        var delegate = new MemoryStore();
        var store = new AuditedConnectionStore(delegate, sink);
        failOn = AuditEvent.Outcome.ATTEMPTED;
        var ex = assertThrows(AuditPersistenceException.class, () -> store.save(CONTEXT, record().build()));
        assertEquals(AuditPersistenceException.OperationState.ATTEMPT_NOT_RECORDED, ex.operationState());
        assertNull(delegate.stored);
        assertEquals(List.of(), calls);
    }

    @Test
    void credentialSuccessfulMutationsRecordAttemptedThenSucceeded() {
        var contextual = new Provider();
        var provider = new AuditedCredentialProvider(contextual, sink);
        provider.put(CONTEXT, "ref-1", "sentinel-secret");
        provider.remove(CONTEXT, "ref-1");
        provider.put(CONTEXT, "-----BEGIN PEM-----", "sentinel-secret");
        CredentialProvider plainDelegate = new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.empty(); }
            @Override public void put(String ref, String secret) { contextual.delegated.add("plain put"); }
            @Override public void remove(String ref) { contextual.delegated.add("plain remove"); }
        };
        var plain = new AuditedCredentialProvider(plainDelegate, sink);
        plain.put(CONTEXT, "ref-2", "sentinel-secret");
        plain.remove(CONTEXT, "ref-2");
        String pem = AuditTargets.opaque("-----BEGIN PEM-----");
        assertEquals(List.of(
                "credential.put|credential|ref-1|null|ATTEMPTED|[]",
                "credential.put|credential|ref-1|null|SUCCEEDED|[]",
                "credential.remove|credential|ref-1|null|ATTEMPTED|[]",
                "credential.remove|credential|ref-1|null|SUCCEEDED|[]",
                "credential.put|credential|" + pem + "|null|ATTEMPTED|[]",
                "credential.put|credential|" + pem + "|null|SUCCEEDED|[]",
                "credential.put|credential|ref-2|null|ATTEMPTED|[]",
                "credential.put|credential|ref-2|null|SUCCEEDED|[]",
                "credential.remove|credential|ref-2|null|ATTEMPTED|[]",
                "credential.remove|credential|ref-2|null|SUCCEEDED|[]"), calls);
        assertEquals(List.of("put(context)", "remove(context)", "put(context)", "plain put", "plain remove"),
                contextual.delegated);
    }

    @Test
    void credentialDelegateFailureRecordsFailedAndRethrowsTheSameInstance() {
        var delegate = new Provider();
        var provider = new AuditedCredentialProvider(delegate, sink);
        var runtime = new IllegalStateException("boom");
        delegate.failure = runtime;
        assertSame(runtime, assertThrows(IllegalStateException.class, () -> provider.put(CONTEXT, "ref-1", "v")));
        var error = new AssertionError("fatal");
        delegate.failure = error;
        assertSame(error, assertThrows(AssertionError.class, () -> provider.remove(CONTEXT, "ref-1")));
        assertEquals(0, runtime.getSuppressed().length);
        assertEquals(0, error.getSuppressed().length);
        assertEquals(List.of(
                "credential.put|credential|ref-1|null|ATTEMPTED|[]",
                "credential.put|credential|ref-1|null|FAILED|[]",
                "credential.remove|credential|ref-1|null|ATTEMPTED|[]",
                "credential.remove|credential|ref-1|null|FAILED|[]"), calls);
    }

    @Test
    void credentialFailedRecordThatFailsIsSuppressedOnTheOriginal() {
        var delegate = new Provider();
        var provider = new AuditedCredentialProvider(delegate, sink);
        var runtime = new IllegalStateException("boom");
        delegate.failure = runtime;
        failOn = AuditEvent.Outcome.FAILED;
        assertSame(runtime, assertThrows(IllegalStateException.class, () -> provider.remove(CONTEXT, "ref-1")));
        assertEquals(1, runtime.getSuppressed().length);
        var suppressed = (AuditPersistenceException) runtime.getSuppressed()[0];
        assertEquals(AuditPersistenceException.OperationState.COMPLETED_ACTION_AUDIT_FAILED,
                suppressed.operationState());
        assertEquals(List.of("credential.remove|credential|ref-1|null|ATTEMPTED|[]"), calls);
    }

    /** Credential wrapper: an audit failure thrown by the delegate propagates with no FAILED event (#172, option a). */
    @Test
    void credentialDelegateAuditFailureSkipsFailedForPutAndRemove() {
        var delegate = new Provider();
        var provider = new AuditedCredentialProvider(delegate, sink);
        var fromPut = delegateAuditFailure();
        delegate.failure = fromPut;
        assertSame(fromPut, assertThrows(AuditPersistenceException.class, () -> provider.put(CONTEXT, "ref-1", "v")));
        var fromRemove = delegateAuditFailure();
        delegate.failure = fromRemove;
        assertSame(fromRemove, assertThrows(AuditPersistenceException.class, () -> provider.remove(CONTEXT, "ref-1")));
        assertEquals(0, fromPut.getSuppressed().length);
        assertEquals(0, fromRemove.getSuppressed().length);
        assertEquals(List.of(
                "credential.put|credential|ref-1|null|ATTEMPTED|[]",
                "credential.remove|credential|ref-1|null|ATTEMPTED|[]"), calls);
    }

    @Test
    void credentialAttemptNotRecordedNeverCallsTheDelegate() {
        var delegate = new Provider();
        var provider = new AuditedCredentialProvider(delegate, sink);
        failOn = AuditEvent.Outcome.ATTEMPTED;
        var ex = assertThrows(AuditPersistenceException.class, () -> provider.put(CONTEXT, "ref-1", "v"));
        assertEquals(AuditPersistenceException.OperationState.ATTEMPT_NOT_RECORDED, ex.operationState());
        assertEquals(List.of(), delegate.delegated);
        assertEquals(List.of(), calls);
    }
}
