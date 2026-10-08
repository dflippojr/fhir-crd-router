package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import static org.junit.jupiter.api.Assertions.*;

class JsonlAuditTrailTest {
    @TempDir Path dir;
    private static final Instant NOW = Instant.parse("2026-10-08T12:00:00Z");
    private static final Clock CLOCK = Clock.fixed(NOW, ZoneOffset.ofHours(-4));

    private AuditContext context(String actor) {
        return new AuditContext(AuditContext.ActorKind.CLIENT, actor, "host-admin-1",
                AuditContext.Source.API, UUID.randomUUID());
    }
    private AuditEvent record(JsonlAuditTrail trail, AuditContext context, AuditEvent.Outcome outcome) {
        return trail.record(context, "connection.save", "connection", "synthetic-payer-1",
                Environment.SANDBOX, outcome, List.of("status"));
    }

    @Test void attributionValidationAndImmutableMetadata() {
        AuditContext unknown = AuditContext.unknown();
        assertEquals(AuditContext.ActorKind.UNKNOWN, unknown.actorKind());
        assertEquals(AuditContext.Source.UNKNOWN, unknown.source());
        assertEquals("unknown", unknown.actorId());
        assertNotEquals(unknown.correlationId(), AuditContext.unknown().correlationId());
        for (String invalid : List.of("", "has space", "https://clinical.example/patient", "bad\nvalue", "x".repeat(129))) {
            assertThrows(IllegalArgumentException.class, () -> context(invalid));
        }
        assertThrows(IllegalArgumentException.class, () -> new AuditContext(AuditContext.ActorKind.UNKNOWN,
                "invented-user", null, AuditContext.Source.UNKNOWN, UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> new AuditContext(AuditContext.ActorKind.UNKNOWN,
                "unknown", "admin", AuditContext.Source.UNKNOWN, UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> new AuditContext(AuditContext.ActorKind.UNKNOWN,
                "unknown", null, AuditContext.Source.CLI, UUID.randomUUID()));
        assertThrows(IllegalArgumentException.class, () -> context(null));
    }

    @Test void concurrentAppendsReopenAndRestore() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        var executor = Executors.newFixedThreadPool(8);
        try (var trail = new JsonlAuditTrail(path, CLOCK)) {
            var tasks = new ArrayList<java.util.concurrent.Callable<AuditEvent>>();
            for (int i = 0; i < 80; i++) {
                AuditContext context = context("client-" + i);
                tasks.add(() -> record(trail, context, AuditEvent.Outcome.ATTEMPTED));
            }
            for (var future : executor.invokeAll(tasks)) assertEquals(NOW, future.get().occurredAt());
            assertThrows(IOException.class, () -> new JsonlAuditTrail(path, CLOCK));
        } finally { executor.shutdownNow(); }
        var events = new AuditReader(path).query(AuditQuery.all(100)).events();
        assertEquals(80, events.size());
        assertEquals(80, events.stream().map(AuditEvent::eventId).distinct().count());
        assertEquals(80, events.stream().map(e -> e.context().actorId()).distinct().count());
        assertEquals(80, events.stream().map(e -> e.context().correlationId()).distinct().count());
        assertTrue(events.stream().allMatch(e -> e.context().source() == AuditContext.Source.API
                && "host-admin-1".equals(e.context().onBehalfOfActorId())));
        Path backup = dir.resolve("backup.jsonl");
        Files.copy(path, backup);
        try (var reopened = new JsonlAuditTrail(path, CLOCK)) {
            record(reopened, AuditContext.unknown(), AuditEvent.Outcome.SUCCEEDED);
        }
        assertEquals(81, new AuditReader(path).query(AuditQuery.all(100)).events().size());
        Files.copy(backup, path, StandardCopyOption.REPLACE_EXISTING);
        assertEquals(events, new AuditReader(path).query(AuditQuery.all(100)).events());
        assertThrows(UnsupportedOperationException.class, () -> events.clear());
    }

    @Test void queryFiltersBoundariesAndExport() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        AuditContext first = context("client-1");
        try (var trail = new JsonlAuditTrail(path, CLOCK)) {
            record(trail, first, AuditEvent.Outcome.ATTEMPTED);
            record(trail, first, AuditEvent.Outcome.SUCCEEDED);
            trail.record(context("client-2"), "credential.resolve", "credential", "synthetic-ref-1",
                    null, AuditEvent.Outcome.FAILED, List.of());
        }
        var reader = new AuditReader(path);
        AuditQuery query = new AuditQuery(NOW, NOW.plusSeconds(1), AuditContext.ActorKind.CLIENT,
                "client-1", "connection", "synthetic-payer-1", "connection.save", first.correlationId(), 1);
        var result = reader.query(query);
        assertEquals(1, result.events().size());
        assertTrue(result.limitReached());
        assertFalse(result.incompleteFinalLine());
        assertEquals(AuditEvent.Outcome.ATTEMPTED, result.events().get(0).outcome());
        for (AuditQuery mismatch : List.of(
                new AuditQuery(null, NOW, null, null, null, null, null, null, 10),
                new AuditQuery(NOW.plusSeconds(1), null, null, null, null, null, null, null, 10),
                new AuditQuery(null, null, AuditContext.ActorKind.SYSTEM, null, null, null, null, null, 10),
                new AuditQuery(null, null, null, "missing", null, null, null, null, 10),
                new AuditQuery(null, null, null, null, "missing", null, null, null, 10),
                new AuditQuery(null, null, null, null, null, "missing", null, null, 10),
                new AuditQuery(null, null, null, null, null, null, "missing", null, 10),
                new AuditQuery(null, null, null, null, null, null, null, UUID.randomUUID(), 10))) {
            assertTrue(reader.query(mismatch).events().isEmpty());
        }
        byte[] before = Files.readAllBytes(path);
        var output = new ByteArrayOutputStream();
        assertEquals(result, reader.exportJsonl(query, output));
        Path exported = dir.resolve("export.jsonl");
        Files.write(exported, output.toByteArray());
        assertEquals(result.events(), new AuditReader(exported).query(AuditQuery.all(10)).events());
        assertArrayEquals(before, Files.readAllBytes(path));
        assertThrows(IllegalArgumentException.class, () -> AuditQuery.all(0));
        assertThrows(IllegalArgumentException.class, () -> AuditQuery.all(10_001));
        assertThrows(IllegalArgumentException.class, () -> new AuditQuery(NOW, NOW, null, null, null, null, null, null, 1));
        assertTrue(new AuditReader(dir.resolve("absent")).query(AuditQuery.all(1)).events().isEmpty());
    }

    @Test void partialTailPreservesHistoryAndCorruptionIsReportedBeyondLimit() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        try (var trail = new JsonlAuditTrail(path, CLOCK)) {
            record(trail, context("client-1"), AuditEvent.Outcome.ATTEMPTED);
        }
        byte[] valid = Files.readAllBytes(path);
        Files.writeString(path, "{\"event\":", StandardOpenOption.APPEND);
        var result = new AuditReader(path).query(AuditQuery.all(1));
        assertTrue(result.incompleteFinalLine());
        assertEquals(1, result.events().size());
        assertThrows(IOException.class, () -> new JsonlAuditTrail(path, CLOCK));
        Files.write(path, valid);
        Files.writeString(path, "broken\n", StandardOpenOption.APPEND);
        assertEquals(2, assertThrows(AuditReadException.class,
                () -> new AuditReader(path).query(AuditQuery.all(1))).lineNumber());
        Files.writeString(path, new String(valid, java.nio.charset.StandardCharsets.UTF_8)
                .replace("client-1", "client-9"));
        assertThrows(AuditReadException.class, () -> new AuditReader(path).query(AuditQuery.all(1)));
        Files.writeString(path, "x".repeat(65_537));
        assertThrows(AuditReadException.class, () -> new AuditReader(path).query(AuditQuery.all(1)));
        Files.writeString(path, "null\n");
        assertThrows(AuditReadException.class, () -> new AuditReader(path).query(AuditQuery.all(1)));
        assertThrows(AuditReadException.class, () -> new AuditReader(dir).query(AuditQuery.all(1)));
    }

    @Test void writeFailuresDistinguishOperationStateAndPoisonWriter() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        AuditContext context = context("client-1");
        try (var trail = new JsonlAuditTrail(path, CLOCK, (channel, line) -> {
            channel.write(ByteBuffer.wrap(new byte[] {'{'}));
            throw new IOException("synthetic-secret-exception");
        })) {
            var failure = assertThrows(AuditPersistenceException.class,
                    () -> record(trail, context, AuditEvent.Outcome.ATTEMPTED));
            assertEquals(AuditPersistenceException.OperationState.ATTEMPT_NOT_RECORDED, failure.operationState());
            assertEquals(context.correlationId(), failure.correlationId());
            assertNotNull(failure.eventId());
            assertNull(failure.getCause());
            assertFalse(failure.toString().contains("synthetic-secret"));
            var completed = assertThrows(AuditPersistenceException.class,
                    () -> record(trail, context, AuditEvent.Outcome.SUCCEEDED));
            assertEquals(AuditPersistenceException.OperationState.COMPLETED_ACTION_AUDIT_FAILED, completed.operationState());
            assertEquals(1, Files.size(path));
        }
        assertTrue(new AuditReader(path).query(AuditQuery.all(1)).incompleteFinalLine());
        Path completedPath = dir.resolve("completed.jsonl");
        int[] calls = {0};
        try (var trail = new JsonlAuditTrail(completedPath, CLOCK, (channel, line) -> {
            if (calls[0]++ == 0) {
                channel.write(ByteBuffer.wrap(line));
                channel.write(ByteBuffer.wrap(new byte[] {'\n'}));
                channel.force(true);
            } else throw new IOException("synthetic-failure");
        })) {
            record(trail, context, AuditEvent.Outcome.ATTEMPTED);
            assertThrows(AuditPersistenceException.class, () -> record(trail, context, AuditEvent.Outcome.FAILED));
        }
        assertEquals(1, new AuditReader(completedPath).query(AuditQuery.all(10)).events().size());
        var closed = new JsonlAuditTrail(dir.resolve("closed.jsonl"), CLOCK);
        closed.close();
        closed.close();
        assertThrows(AuditPersistenceException.class, () -> record(closed, context, AuditEvent.Outcome.ATTEMPTED));
    }

    @Test void permissionsAndSafeSerialization() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        try (var trail = new JsonlAuditTrail(path, CLOCK)) {
            AuditEvent event = record(trail, context("client-1"), AuditEvent.Outcome.SUCCEEDED);
            assertThrows(UnsupportedOperationException.class, () -> event.changedFields().clear());
            String serialized = new String(AuditJson.encode(event), java.nio.charset.StandardCharsets.UTF_8)
                    + event + event.context();
            for (String sentinel : List.of("synthetic-secret", "access_token", "BEGIN PRIVATE KEY",
                    "Authorization", "Patient/", "https://", "exception-sentinel")) {
                assertFalse(serialized.contains(sentinel));
            }
            if (Files.getFileAttributeView(path, PosixFileAttributeView.class) != null) {
                assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(path));
            } else {
                var acl = Files.getFileAttributeView(path, AclFileAttributeView.class);
                assertNotNull(acl);
                assertFalse(acl.getAcl().isEmpty());
                var owner = acl.getOwner();
                assertTrue(acl.getAcl().stream().allMatch(e -> e.principal().equals(owner)));
                assertTrue(acl.getAcl().get(0).permissions().contains(AclEntryPermission.READ_DATA));
            }
        }
        assertThrows(IOException.class, () -> new JsonlAuditTrail(dir.resolve("missing/audit.jsonl"), CLOCK));
        var context = context("client-1");
        assertThrows(IllegalArgumentException.class, () -> new AuditEvent(2, UUID.randomUUID(), NOW,
                context, "save", "connection", "synthetic-1", null, AuditEvent.Outcome.SUCCEEDED, List.of()));
        assertThrows(IllegalArgumentException.class, () -> new AuditEvent(1, UUID.randomUUID(), NOW,
                context, "save", "connection", "synthetic-1", null, AuditEvent.Outcome.SUCCEEDED,
                java.util.Collections.nCopies(65, "status")));
    }
}
