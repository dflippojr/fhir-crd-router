package io.github.dflippojr.fhircrdrouter.credential.local;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditContext;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditEvent;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditPersistenceException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditQuery;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditReader;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditedCredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.audit.JsonlAuditTrail;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AuditedCredentialAccessTest {

    private static final String SECRET = "sentinel-secret-value-123";
    private static final AuditContext CONTEXT = new AuditContext(AuditContext.ActorKind.SYSTEM, "job-runner",
            "owner-1", AuditContext.Source.JOB, UUID.randomUUID());

    /** A closed trail rejects every append, like a failed audit volume. */
    private static AuditSink brokenSink(Path dir) throws IOException {
        var trail = new JsonlAuditTrail(dir.resolve("closed.jsonl"), Clock.systemUTC());
        trail.close();
        return trail;
    }

    private static List<AuditEvent> events(Path file) {
        return new AuditReader(file).query(AuditQuery.all(1000)).events();
    }

    @Test
    void putResolveRemoveAndKeyCreationAreAuditedWithoutSecrets(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("events.jsonl");
        Path store = dir.resolve("creds");
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            var provider = new AuditedCredentialProvider(new EncryptedLocalCredentialProvider(store, trail), trail);
            provider.put(CONTEXT, "ref-1", SECRET);
            provider.put(CONTEXT, "ref-1", SECRET + "2"); // replace; key must not be created again
            assertTrue(provider.resolve(CONTEXT, "ref-1").isPresent());
            assertTrue(provider.resolve(CONTEXT, "missing").isEmpty());
            provider.remove(CONTEXT, "ref-1");
            // A fresh instance loading the existing key is not a creation.
            var reopened = new AuditedCredentialProvider(new EncryptedLocalCredentialProvider(store, trail), trail);
            reopened.put(CONTEXT, "ref-2", SECRET);
        }
        List<AuditEvent> all = events(file);
        assertEquals(List.of(
                "credential.put:ATTEMPTED", "credential.key.create:ATTEMPTED", "credential.key.create:SUCCEEDED",
                "credential.put:SUCCEEDED", "credential.put:ATTEMPTED", "credential.put:SUCCEEDED",
                "credential.resolve.found:SUCCEEDED", "credential.resolve.not_found:SUCCEEDED",
                "credential.remove:ATTEMPTED", "credential.remove:SUCCEEDED",
                "credential.put:ATTEMPTED", "credential.put:SUCCEEDED"),
                all.stream().map(e -> e.action() + ":" + e.outcome()).toList());
        assertEquals("local-key-store", all.get(1).targetKind());
        assertFalse(all.get(1).targetId().contains(dir.getFileName().toString()));
        for (AuditEvent e : all) {
            assertEquals("job-runner", e.context().actorId());
            assertEquals("owner-1", e.context().onBehalfOfActorId());
        }
        assertFalse((Files.readString(file) + all).contains("sentinel"));
    }

    @Test
    void decryptFailureIsAuditedWithFixedReasonCode(@TempDir Path dir) throws IOException {
        Path file = dir.resolve("events.jsonl");
        Path store = dir.resolve("creds");
        new EncryptedLocalCredentialProvider(store).put("ref-1", SECRET);
        Files.write(store.resolve("key.bin"), new byte[32]); // wrong key for the stored ciphertext
        try (var trail = new JsonlAuditTrail(file, Clock.systemUTC())) {
            var provider = new AuditedCredentialProvider(new EncryptedLocalCredentialProvider(store, trail), trail);
            assertThrows(IllegalStateException.class, () -> provider.resolve(CONTEXT, "ref-1"));
        }
        List<AuditEvent> all = events(file);
        assertEquals(1, all.size());
        assertEquals("credential.resolve.failed.provider_error", all.get(0).action());
        assertEquals(AuditEvent.Outcome.FAILED, all.get(0).outcome());
        assertFalse(Files.readString(file).toLowerCase().contains("decrypt"));
    }

    @Test
    void auditFailureBeforePutLeavesNoSecretAndNoKey(@TempDir Path dir) throws IOException {
        AuditSink broken = brokenSink(dir);
        Path store = dir.resolve("creds");
        var provider = new AuditedCredentialProvider(new EncryptedLocalCredentialProvider(store, broken), broken);
        var ex = assertThrows(AuditPersistenceException.class, () -> provider.put(CONTEXT, "ref-1", SECRET));
        assertEquals(AuditPersistenceException.OperationState.ATTEMPT_NOT_RECORDED, ex.operationState());
        assertFalse(Files.exists(store.resolve("key.bin")));
        assertFalse(Files.exists(store.resolve("secrets.properties")));
    }

    @Test
    void keyAuditAttemptFailureCreatesNoKeyEvenWithoutOuterWrapper(@TempDir Path dir) throws IOException {
        AuditSink broken = brokenSink(dir);
        var provider = new EncryptedLocalCredentialProvider(dir, broken);
        assertThrows(AuditPersistenceException.class, () -> provider.put(CONTEXT, "ref-1", SECRET));
        assertFalse(Files.exists(dir.resolve("key.bin")));
    }

    @Test
    void resolveDiscardsSecretWhenCompletionCannotBeRecorded(@TempDir Path dir) throws IOException {
        AuditSink broken = brokenSink(dir);
        new EncryptedLocalCredentialProvider(dir).put("ref-1", SECRET);
        var provider = new AuditedCredentialProvider(new EncryptedLocalCredentialProvider(dir), broken);
        var ex = assertThrows(AuditPersistenceException.class, () -> provider.resolve(CONTEXT, "ref-1"));
        assertEquals(AuditPersistenceException.OperationState.COMPLETED_ACTION_AUDIT_FAILED, ex.operationState());
    }

    @Test
    void auditDisabledConstructorBehavesAsBefore(@TempDir Path dir) {
        var plain = new EncryptedLocalCredentialProvider(dir);
        plain.put("ref-1", SECRET);
        assertEquals(SECRET, plain.resolve("ref-1").orElseThrow());
        plain.remove("ref-1");
        assertTrue(plain.resolve("ref-1").isEmpty());
    }
}
