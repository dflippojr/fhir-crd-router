package io.github.dflippojr.fhircrdrouter.core.audit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.InvalidConnectionRecordException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** #231: an entry the store cannot read can still be repaired or deleted through the audited wrapper. */
class AuditedConnectionStoreInvalidEntryTest {

    private static final String BROKEN = """
            - payerId: "PAYER-BAD"
              environment: "PRODUCTION"
              baseUrl: "https://bad.example/r4"
              authType: "OAUTH2_CLIENT_CREDENTIALS"
              tokenEndpoint: "https://auth.example/token"
            """;

    private static final AuditContext CONTEXT = new AuditContext(AuditContext.ActorKind.CLIENT, "cli-user",
            null, AuditContext.Source.CLI, UUID.randomUUID());

    private static List<AuditEvent> succeeded(Path events) {
        return new AuditReader(events).query(AuditQuery.all(100)).events().stream()
                .filter(e -> e.outcome() == AuditEvent.Outcome.SUCCEEDED).toList();
    }

    @Test
    void saveOverAnUnreadableEntryRepairsItAndIsRecordedAsAnUpdate(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("c.yaml");
        Files.writeString(file, BROKEN);
        Path events = dir.resolve("events.jsonl");
        try (var trail = new JsonlAuditTrail(events, Clock.systemUTC())) {
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(file), trail);
            assertThrows(InvalidConnectionRecordException.class,
                    () -> store.findByPayerIdAndEnvironment("PAYER-BAD", Environment.PRODUCTION));

            store.save(CONTEXT, ConnectionRecord.builder().payerId("PAYER-BAD").environment(Environment.PRODUCTION)
                    .baseUrl("https://bad.example/r4").authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                    .tokenEndpoint("https://auth.example/token").clientId("client").build());

            assertEquals("client", store.findByPayerIdAndEnvironment("PAYER-BAD", Environment.PRODUCTION)
                    .orElseThrow().clientId());
        }
        List<AuditEvent> done = succeeded(events);
        assertEquals(List.of("connection.update"), done.stream().map(AuditEvent::action).toList());
        assertEquals(List.of("baseUrl", "authType", "tokenEndpoint", "clientId", "status"),
                done.get(0).changedFields());
    }

    @Test
    void deleteOfAnUnreadableEntryIsRecordedAsADelete(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("c.yaml");
        Files.writeString(file, BROKEN);
        Path events = dir.resolve("events.jsonl");
        try (var trail = new JsonlAuditTrail(events, Clock.systemUTC())) {
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(file), trail);

            store.delete(CONTEXT, "PAYER-BAD", Environment.PRODUCTION);

            assertEquals(List.of(), store.findByPayerId("PAYER-BAD"));
        }
        assertEquals(List.of("connection.delete"), succeeded(events).stream().map(AuditEvent::action).toList());
    }
}
