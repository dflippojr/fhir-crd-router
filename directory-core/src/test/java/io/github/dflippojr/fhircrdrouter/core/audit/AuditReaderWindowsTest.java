package io.github.dflippojr.fhircrdrouter.core.audit;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/** #72: Windows enforces file locks against readers; run on every OS, including hosted Windows. */
class AuditReaderWindowsTest {
    @TempDir Path dir;

    @Test
    void readsAndExportsAcknowledgedEventsWhileWriterRemainsOpen() throws Exception {
        Path path = dir.resolve("audit.jsonl");
        AuditReader reader = new AuditReader(path);
        try (var writer = new JsonlAuditTrail(path, Clock.systemUTC())) {
            AuditEvent first = writer.record(AuditContext.unknown(), "connection.save", "connection",
                    "synthetic-payer", null, AuditEvent.Outcome.ATTEMPTED, List.of());
            assertEquals(List.of(first), reader.query(AuditQuery.all(10)).events());

            var exported = new ByteArrayOutputStream();
            assertEquals(List.of(first), reader.exportJsonl(AuditQuery.all(10), exported).events());
            assertEquals(AuditJson.encode(first).length + 1, exported.size());
            assertThrows(IOException.class, () -> new JsonlAuditTrail(path, Clock.systemUTC()));

            AuditEvent second = writer.record(AuditContext.unknown(), "connection.save", "connection",
                    "synthetic-payer", null, AuditEvent.Outcome.SUCCEEDED, List.of());
            AuditReader.Result result = reader.query(AuditQuery.all(10));
            assertEquals(List.of(first, second), result.events());
            assertFalse(result.incompleteFinalLine());
        }
        assertEquals(2, reader.query(AuditQuery.all(10)).events().size());
    }
}
