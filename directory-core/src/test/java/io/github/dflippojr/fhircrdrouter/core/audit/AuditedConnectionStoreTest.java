package io.github.dflippojr.fhircrdrouter.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditedConnectionStoreTest {

    private static final String URL_SENTINEL = "https://secret-host.example.invalid/sentinel-path";
    private static final String CONTACT_SENTINEL = "sentinel-contact@example.invalid";

    private static AuditContext ctx(String actor, String onBehalfOf, AuditContext.Source source) {
        return new AuditContext(AuditContext.ActorKind.CLIENT, actor, onBehalfOf, source, UUID.randomUUID());
    }

    private static ConnectionRecord.Builder base() {
        return ConnectionRecord.builder().payerId("synthetic-payer").environment(Environment.SANDBOX)
                .baseUrl(URL_SENTINEL).authType(AuthType.NONE).contactInfo(CONTACT_SENTINEL);
    }

    private static List<AuditEvent> events(Path file) {
        return new AuditReader(file).query(AuditQuery.all(1000)).events();
    }

    private static AuditPersistenceException persistenceFailure(AuditContext c, String a, String k, String t,
                                                                Environment env, AuditEvent.Outcome o,
                                                                List<String> f) {
        return new AuditPersistenceException(new AuditEvent(1, UUID.randomUUID(), Instant.now(), c, a, k, t, env, o, f));
    }

    @Test
    void createUpdateAuthChangeDeleteAndMissingDeleteLeaveHistoryAfterReopen(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("events.jsonl");
        AuditContext context = ctx("cli-user", "delegator-1", AuditContext.Source.CLI);
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(dir.resolve("c.yaml")), trail);
            store.save(context, base().build());
            store.save(context, base().status(ConnectionStatus.INACTIVE).build());
            store.save(context, base().status(ConnectionStatus.INACTIVE)
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint("https://t.invalid/x")
                    .clientId("cid").credentialRef("ref-1").build());
            store.save(context, base().status(ConnectionStatus.INACTIVE)
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint("https://t.invalid/x")
                    .clientId("cid").credentialRef("ref-1").createdAt(Instant.EPOCH).updatedAt(Instant.EPOCH).build());
            store.delete(context, "synthetic-payer", Environment.SANDBOX);
            store.delete(context, "synthetic-payer", Environment.SANDBOX);
        }
        List<AuditEvent> all = events(file); // reopened reader: history outlives the deleted record
        List<AuditEvent> completed = all.stream().filter(e -> e.outcome() == AuditEvent.Outcome.SUCCEEDED).toList();
        assertEquals(List.of("connection.create", "connection.update", "connection.update",
                "connection.no_change", "connection.delete", "connection.delete_missing"),
                completed.stream().map(AuditEvent::action).toList());
        assertEquals(12, all.size());
        assertEquals(List.of("status"), completed.get(1).changedFields());
        assertEquals(List.of("authType", "tokenEndpoint", "clientId", "credentialRef"), completed.get(2).changedFields());
        assertEquals(List.of(), completed.get(3).changedFields());
        for (AuditEvent e : all) {
            assertEquals("cli-user", e.context().actorId());
            assertEquals("delegator-1", e.context().onBehalfOfActorId());
            assertEquals(AuditContext.Source.CLI, e.context().source());
            assertEquals("connection", e.targetKind());
            assertEquals("synthetic-payer", e.targetId());
            assertEquals(Environment.SANDBOX, e.environment());
            assertEquals(context.correlationId(), e.context().correlationId());
            assertTrue(e.occurredAt() != null);
        }
        String bytes = Files.readString(file) + all;
        assertFalse(bytes.contains("sentinel"));
        assertFalse(bytes.contains("ref-1"));
    }

    @Test
    void delegateFailureIsRecordedAsFailedNeverSucceeded() {
        List<AuditEvent.Outcome> outcomes = new ArrayList<>();
        AuditSink sink = (c, a, k, t, env, o, f) -> {
            outcomes.add(o);
            return null;
        };
        ConnectionStore broken = new ConnectionStoreStub() {
            @Override public void save(ConnectionRecord record) {
                throw new IllegalStateException("boom");
            }
        };
        var store = new AuditedConnectionStore(broken, sink);
        assertThrows(IllegalStateException.class,
                () -> store.save(ctx("a", null, AuditContext.Source.API), base().build()));
        assertEquals(List.of(AuditEvent.Outcome.ATTEMPTED, AuditEvent.Outcome.FAILED), outcomes);
    }

    @Test
    void attemptFailureSkipsMutationAndCompletionFailureReportsCommitted() {
        List<String> calls = new ArrayList<>();
        ConnectionStore delegate = new ConnectionStoreStub() {
            @Override public void save(ConnectionRecord record) {
                calls.add("save");
            }
        };
        AuditSink noAttempt = (c, a, k, t, env, o, f) -> {
            throw persistenceFailure(c, a, k, t, env, o, f);
        };
        var ex = assertThrows(AuditPersistenceException.class,
                () -> new AuditedConnectionStore(delegate, noAttempt).save(AuditContext.unknown(), base().build()));
        assertEquals(AuditPersistenceException.OperationState.ATTEMPT_NOT_RECORDED, ex.operationState());
        assertTrue(calls.isEmpty());

        AuditSink noCompletion = (c, a, k, t, env, o, f) -> {
            if (o == AuditEvent.Outcome.SUCCEEDED) throw persistenceFailure(c, a, k, t, env, o, f);
            return null;
        };
        var ex2 = assertThrows(AuditPersistenceException.class,
                () -> new AuditedConnectionStore(delegate, noCompletion).save(AuditContext.unknown(), base().build()));
        assertEquals(AuditPersistenceException.OperationState.COMPLETED_ACTION_AUDIT_FAILED, ex2.operationState());
        assertEquals(List.of("save"), calls);
    }

    @Test
    void concurrentActorsKeepTheirOwnContext(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("events.jsonl");
        int n = 8;
        ExecutorService pool = Executors.newFixedThreadPool(n);
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(dir.resolve("c.yaml")), trail);
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                final int id = i;
                futures.add(pool.submit(() -> store.save(ctx("actor-" + id, null, AuditContext.Source.JOB),
                        base().payerId("payer-" + id).build())));
            }
            for (Future<?> f : futures) f.get();
        } finally {
            pool.shutdownNow();
        }
        List<AuditEvent> all = events(file);
        assertEquals(2 * n, all.size());
        for (AuditEvent e : all) {
            assertEquals(e.targetId().replace("payer-", "actor-"), e.context().actorId());
            assertEquals("connection.create", e.action());
        }
    }

    @Test
    void plainInterfaceUsesUnknownAttributionAndReadsPassThrough(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("events.jsonl");
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            ConnectionStore store = new AuditedConnectionStore(new FileBasedConnectionStore(dir.resolve("c.yaml")), trail);
            store.save(base().build());
            assertEquals(1, store.findAll().size());
            assertTrue(store.findByPayerIdAndEnvironment("synthetic-payer", Environment.SANDBOX).isPresent());
            assertEquals(1, store.findByPayerId("synthetic-payer").size());
        }
        assertEquals(2, events(file).size());
        assertEquals(AuditContext.ActorKind.UNKNOWN, events(file).get(0).context().actorKind());
    }

    @Test
    void unsafePayerIdBecomesOpaqueTarget(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("events.jsonl");
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(dir.resolve("c.yaml")), trail);
            store.save(AuditContext.unknown(), base().payerId("payer with spaces/and slash").build());
        }
        String target = events(file).get(0).targetId();
        assertTrue(target.startsWith("ref-"));
        assertFalse(Files.readString(file).contains("spaces"));
    }

    /** Minimal store for failure injection. */
    private static class ConnectionStoreStub implements ConnectionStore {
        @Override public List<ConnectionRecord> findByPayerId(String payerId) { return List.of(); }
        @Override public Optional<ConnectionRecord> findByPayerIdAndEnvironment(String p, Environment e) {
            return Optional.empty();
        }
        @Override public List<ConnectionRecord> findAll() { return List.of(); }
        @Override public void save(ConnectionRecord record) { }
        @Override public void delete(String payerId, Environment environment) { }
    }
}
