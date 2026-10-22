package io.github.dflippojr.fhircrdrouter.credential.local;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditContext;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditQuery;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditReader;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditedCredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.audit.JsonlAuditTrail;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.util.Optional;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** A null {@code credentialRef} is a caller bug: it fails fast, before any lock, lookup or audit event. */
class NullCredentialRefTest {

    private static void assertNamesCredentialRef(Runnable call) {
        NullPointerException e = assertThrows(NullPointerException.class, call::run);
        assertTrue(e.getMessage() != null && e.getMessage().contains("credentialRef"),
                "message should name credentialRef but was: " + e.getMessage());
    }

    private static void assertAllNullCallsRejected(EncryptedLocalCredentialProvider provider) {
        AuditContext ctx = AuditContext.unknown();
        assertNamesCredentialRef(() -> provider.resolve(null));
        assertNamesCredentialRef(() -> provider.resolve(ctx, null));
        assertNamesCredentialRef(() -> provider.put(null, "v"));
        assertNamesCredentialRef(() -> provider.put(ctx, null, "v"));
        assertNamesCredentialRef(() -> provider.remove(null));
        assertNamesCredentialRef(() -> provider.remove(ctx, null));
    }

    @Test
    void nullRefIsRejectedOnAnEmptyStore(@TempDir Path dir) {
        assertAllNullCallsRejected(new EncryptedLocalCredentialProvider(dir.resolve("creds")));
    }

    @Test
    void nullRefIsRejectedOnAStoreWithEntries(@TempDir Path dir) {
        var provider = new EncryptedLocalCredentialProvider(dir.resolve("creds"));
        provider.put("ref-1", "secret");
        assertAllNullCallsRejected(provider);
        assertEquals(Optional.of("secret"), provider.resolve("ref-1"));
    }

    @Test
    void nullPutDoesNotStoreAnEntryOrCreateAKey(@TempDir Path dir) {
        Path store = dir.resolve("creds");
        var provider = new EncryptedLocalCredentialProvider(store);
        assertNamesCredentialRef(() -> provider.put(null, "v"));
        assertFalse(Files.exists(store), "a rejected put must not touch the store directory");
    }

    @Test
    void missingRefStillResolvesToEmpty(@TempDir Path dir) {
        var provider = new EncryptedLocalCredentialProvider(dir.resolve("creds"));
        assertEquals(Optional.empty(), provider.resolve("missing"));
        provider.put("ref-1", "secret");
        assertEquals(Optional.empty(), provider.resolve("missing"));
    }

    @Test
    void auditedProviderWritesNoEventForANullRef(@TempDir Path dir) throws IOException {
        Path events = dir.resolve("events.jsonl");
        try (var trail = new JsonlAuditTrail(events, Clock.systemUTC())) {
            var provider = new AuditedCredentialProvider(
                    new EncryptedLocalCredentialProvider(dir.resolve("creds"), trail), trail);
            AuditContext ctx = AuditContext.unknown();
            for (Consumer<AuditedCredentialProvider> call : java.util.List.<Consumer<AuditedCredentialProvider>>of(
                    p -> p.resolve(null), p -> p.resolve(ctx, null), p -> p.put(null, "v"),
                    p -> p.put(ctx, null, "v"), p -> p.remove(null), p -> p.remove(ctx, null))) {
                assertNamesCredentialRef(() -> call.accept(provider));
            }
        }
        assertTrue(Files.notExists(events) || new AuditReader(events).query(AuditQuery.all(1000)).events().isEmpty(),
                "no audit event may be written for a null reference");
    }
}
