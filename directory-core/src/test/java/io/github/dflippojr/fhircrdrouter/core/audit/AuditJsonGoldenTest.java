package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;

/** Pins the exact checksum bytes of a fixed event and the shared SHA-256 hex helper, so a refactor cannot change them. */
class AuditJsonGoldenTest {
    private static final AuditEvent EVENT = new AuditEvent(1,
            UUID.fromString("00000000-0000-4000-8000-000000000001"), Instant.parse("2026-10-08T12:00:00Z"),
            new AuditContext(AuditContext.ActorKind.CLIENT, "host-app", null, AuditContext.Source.API,
                    UUID.fromString("00000000-0000-4000-8000-000000000002")),
            "connection.save", "connection", "synthetic-payer-1", Environment.SANDBOX,
            AuditEvent.Outcome.SUCCEEDED, List.of("status"));
    /** Recorded on master; sha256 is SHA-256 of the event's JSON bytes (checked with sha256sum). */
    private static final String LINE = """
            {"event":{"schemaVersion":1,"eventId":"00000000-0000-4000-8000-000000000001",\
            "occurredAt":"2026-10-08T12:00:00Z","context":{"actorKind":"CLIENT","actorId":"host-app",\
            "onBehalfOfActorId":null,"source":"API","correlationId":"00000000-0000-4000-8000-000000000002"},\
            "action":"connection.save","targetKind":"connection","targetId":"synthetic-payer-1",\
            "environment":"SANDBOX","outcome":"SUCCEEDED","changedFields":["status"]},\
            "sha256":"43a667b1d0952812259ebd83c11445c01c6ac72abe932a8f8411b94197fcd39c"}""";

    @Test void encodesFixedEventWithPinnedChecksum() throws IOException {
        assertEquals(LINE, new String(AuditJson.encode(EVENT), StandardCharsets.UTF_8));
    }

    @Test void decodesPinnedLineAndRejectsAlteredChecksum() throws IOException {
        assertEquals(EVENT, AuditJson.decode(LINE.getBytes(StandardCharsets.UTF_8)));
        String altered = LINE.replace("\"sha256\":\"43a6", "\"sha256\":\"0000");
        assertNotEquals(LINE, altered);
        assertThrows(IOException.class, () -> AuditJson.decode(altered.getBytes(StandardCharsets.UTF_8)));
    }

    @Test void sharedDigestPinsEmptyAndNonAsciiInput() {
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", AuditTargets.digest("", 64));
        assertEquals("ce335642bab85530c756f72c1afb3bfc2067dd39b92e2368e4475c8dbeacc48e",
                AuditTargets.digest("café ☃", 64));
        assertEquals("ce335642bab85530", AuditTargets.digest("café ☃", 16));
    }
}
