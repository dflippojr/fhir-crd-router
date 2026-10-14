package io.github.dflippojr.fhircrdrouter.credential.local;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditContext;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditEvent;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class EncryptedLocalCredentialProviderDurabilityTest {

    private static final String SECRET = "synthetic-secret";

    /** Writes a little, then fails, like a disk filling up mid-write. */
    private static OutputStream failingMidway(OutputStream out) {
        return new FilterOutputStream(out) {
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                out.write(b, off, Math.min(len, 10));
                throw new IOException("simulated disk full");
            }
        };
    }

    private static EncryptedLocalCredentialProvider failingWriter(Path dir) {
        return new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO, System::nanoTime,
                EncryptedLocalCredentialProviderDurabilityTest::failingMidway);
    }

    private static long tmpFileCount(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".tmp")).count();
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    // #61

    @Test
    void concurrentWritesFromAnotherInstanceNeverHideAStoredSecret(@TempDir Path dir) throws Exception {
        var writer = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        writer.put("stable", SECRET);
        for (int i = 0; i < 200; i++) {
            writer.put("filler-" + i, "x".repeat(200));
        }
        var reader = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        AtomicBoolean stop = new AtomicBoolean();
        AtomicInteger empties = new AtomicInteger();
        AtomicInteger reads = new AtomicInteger();
        List<Throwable> errors = Collections.synchronizedList(new ArrayList<>());
        Thread t = new Thread(() -> {
            while (!stop.get()) {
                reads.incrementAndGet();
                try {
                    if (reader.resolve("stable").isEmpty()) {
                        empties.incrementAndGet();
                    }
                } catch (RuntimeException e) {
                    errors.add(e);
                }
            }
        });
        t.start();
        try {
            for (int i = 0; i < 300; i++) {
                writer.put("churn", "value-" + i);
            }
        } finally {
            stop.set(true);
            t.join();
        }

        assertTrue(reads.get() > 0);
        assertEquals(List.of(), errors);
        assertEquals(0, empties.get(), "empty results out of " + reads.get() + " reads");
        assertEquals(0, tmpFileCount(dir));
    }

    @Test
    void failureMidWriteKeepsPreviousFileByteIdentical(@TempDir Path dir) throws Exception {
        var plain = new EncryptedLocalCredentialProvider(dir);
        plain.put("a", SECRET);
        plain.put("b", SECRET + "-b");
        Path secrets = dir.resolve("secrets.properties");
        byte[] before = Files.readAllBytes(secrets);

        var broken = failingWriter(dir);
        assertThrows(UncheckedIOException.class, () -> broken.put("c", "new"));
        assertThrows(UncheckedIOException.class, () -> broken.remove("a"));

        assertArrayEquals(before, Files.readAllBytes(secrets));
        var reopened = new EncryptedLocalCredentialProvider(dir);
        assertEquals(SECRET, reopened.resolve("a").orElseThrow());
        assertEquals(SECRET + "-b", reopened.resolve("b").orElseThrow());
        assertTrue(reopened.resolve("c").isEmpty());
        assertEquals(0, tmpFileCount(dir));
    }

    @Test
    void failureWritingANewKeyLeavesNoKeyAndNoTempFile(@TempDir Path dir) throws Exception {
        assertThrows(UncheckedIOException.class, () -> failingWriter(dir).put("a", SECRET));

        assertFalse(Files.exists(dir.resolve("key.bin")));
        assertFalse(Files.exists(dir.resolve("secrets.properties")));
        assertEquals(0, tmpFileCount(dir));
        var healthy = new EncryptedLocalCredentialProvider(dir);
        healthy.put("a", SECRET);
        assertEquals(SECRET, healthy.resolve("a").orElseThrow());
    }

    @Test
    void filesAreOwnerOnlyWherePosixApplies(@TempDir Path dir) throws Exception {
        assumeTrue(FileSystems.getDefault().supportedFileAttributeViews().contains("posix"));
        var provider = new EncryptedLocalCredentialProvider(dir);
        provider.put("a", SECRET);
        provider.put("b", SECRET);

        for (String name : List.of("key.bin", "secrets.properties")) {
            assertEquals("rw-------",
                    PosixFilePermissions.toString(Files.getPosixFilePermissions(dir.resolve(name))), name);
        }
    }

    // #62

    @Test
    void concurrentFirstUsePublishesExactlyOneKey(@TempDir Path root) throws Exception {
        int undecryptable = 0;
        List<String> keyEvents = Collections.synchronizedList(new ArrayList<>());
        AuditSink sink = (context, action, targetKind, targetId, environment, outcome, changedFields) -> {
            if (action.equals("credential.key.create")) {
                keyEvents.add(outcome.name());
            }
            return null;
        };
        int runs = 40;
        for (int run = 0; run < runs; run++) {
            Path dir = root.resolve("r" + run);
            var a = new EncryptedLocalCredentialProvider(dir, sink);
            var b = new EncryptedLocalCredentialProvider(dir, sink);
            CountDownLatch go = new CountDownLatch(1);
            Thread ta = new Thread(() -> { await(go); a.put("a", "secret-a"); });
            Thread tb = new Thread(() -> { await(go); b.put("b", "secret-b"); });
            ta.start();
            tb.start();
            go.countDown();
            ta.join();
            tb.join();

            var check = new EncryptedLocalCredentialProvider(dir);
            for (String ref : List.of("a", "b")) {
                try {
                    check.resolve(ref);
                } catch (IllegalStateException e) {
                    undecryptable++;
                }
            }
            assertEquals(0, tmpFileCount(dir));
        }

        assertEquals(0, undecryptable);
        assertEquals(runs, Collections.frequency(keyEvents, "SUCCEEDED"));
        assertEquals(Collections.frequency(keyEvents, "ATTEMPTED"),
                Collections.frequency(keyEvents, "SUCCEEDED") + Collections.frequency(keyEvents, "FAILED"));
    }

    @Test
    void anExistingKeyIsNeverReplaced(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        byte[] original = Files.readAllBytes(dir.resolve("key.bin"));

        new EncryptedLocalCredentialProvider(dir).put("b", SECRET);
        new EncryptedLocalCredentialProvider(dir).remove("a");
        new EncryptedLocalCredentialProvider(dir).remove("b");
        new EncryptedLocalCredentialProvider(dir).put("c", SECRET); // empty store, key already present

        assertArrayEquals(original, Files.readAllBytes(dir.resolve("key.bin")));
    }

    // #64

    @Test
    void resolveNeverCreatesAKeyAndNamesTheMissingKey(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        byte[] original = Files.readAllBytes(dir.resolve("key.bin"));
        Files.delete(dir.resolve("key.bin"));
        byte[] secretsBefore = Files.readAllBytes(dir.resolve("secrets.properties"));
        List<String> actions = Collections.synchronizedList(new ArrayList<>());
        AuditSink sink = (context, action, targetKind, targetId, environment, outcome, changedFields) -> {
            actions.add(action);
            return null;
        };
        var fresh = new EncryptedLocalCredentialProvider(dir, sink);

        var resolveError = assertThrows(IllegalStateException.class, () -> fresh.resolve(AuditContext.unknown(), "a"));
        assertTrue(resolveError.getMessage().contains("key is missing"), resolveError.getMessage());
        assertFalse(resolveError.getMessage().contains("Failed to decrypt"));
        assertFalse(Files.exists(dir.resolve("key.bin")));

        var putError = assertThrows(IllegalStateException.class, () -> fresh.put(AuditContext.unknown(), "b", "second"));
        assertTrue(putError.getMessage().contains("key is missing"), putError.getMessage());
        assertFalse(Files.exists(dir.resolve("key.bin")));
        assertArrayEquals(secretsBefore, Files.readAllBytes(dir.resolve("secrets.properties")));
        assertEquals(List.of(), actions);

        Files.write(dir.resolve("key.bin"), original); // the owner restores the backup
        var restored = new EncryptedLocalCredentialProvider(dir);
        assertEquals(SECRET, restored.resolve("a").orElseThrow());
        restored.put("b", "second");
        assertEquals("second", new EncryptedLocalCredentialProvider(dir).resolve("b").orElseThrow());
    }

    @Test
    void putOnANewOrEmptiedStoreStillCreatesTheKey(@TempDir Path dir) throws Exception {
        var provider = new EncryptedLocalCredentialProvider(dir.resolve("new"));
        provider.put("a", SECRET);
        assertTrue(Files.exists(dir.resolve("new").resolve("key.bin")));

        Path emptied = dir.resolve("emptied");
        var first = new EncryptedLocalCredentialProvider(emptied);
        first.put("a", SECRET);
        first.remove("a");
        Files.delete(emptied.resolve("key.bin"));
        var second = new EncryptedLocalCredentialProvider(emptied);
        second.put("b", SECRET);
        assertEquals(SECRET, new EncryptedLocalCredentialProvider(emptied).resolve("b").orElseThrow());
    }

    // #65

    @Test
    void corruptEntriesFailWithAClearErrorAndNoCiphertext(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        Files.writeString(dir.resolve("secrets.properties"), "short=AAAA\nbad=!!!notbase64\n");

        for (String ref : List.of("short", "bad")) {
            var provider = new EncryptedLocalCredentialProvider(dir);
            var e = assertThrows(IllegalStateException.class, () -> provider.resolve(ref));
            assertTrue(e.getMessage().contains("Corrupt credential entry '" + ref + "'"), e.getMessage());
            assertFalse(e.getMessage().contains("AAAA"));
            assertFalse(e.getMessage().contains("notbase64"));
            assertNull(e.getCause());
        }
    }

    @Test
    void keysThatAreNot256BitsAreRejectedForResolveAndPut(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        byte[] secretsBefore = Files.readAllBytes(dir.resolve("secrets.properties"));

        for (int size : new int[] {0, 16, 31, 33}) {
            Files.write(dir.resolve("key.bin"), new byte[size]);
            var resolveError = assertThrows(IllegalStateException.class,
                    () -> new EncryptedLocalCredentialProvider(dir).resolve("a"));
            assertTrue(resolveError.getMessage().contains("not a 256-bit AES key"), resolveError.getMessage());
            var putError = assertThrows(IllegalStateException.class,
                    () -> new EncryptedLocalCredentialProvider(dir).put("z", "v"));
            assertTrue(putError.getMessage().contains("not a 256-bit AES key"), putError.getMessage());
            assertEquals(size, Files.size(dir.resolve("key.bin")));
        }
        assertArrayEquals(secretsBefore, Files.readAllBytes(dir.resolve("secrets.properties")));
    }

    @Test
    void aWrongKeyStillReportsADecryptFailureForTheRef(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        Files.write(dir.resolve("key.bin"), new byte[32]);

        var e = assertThrows(IllegalStateException.class, () -> new EncryptedLocalCredentialProvider(dir).resolve("a"));
        assertTrue(e.getMessage().contains("Failed to decrypt credential 'a'"), e.getMessage());
        assertFalse(e.getMessage().contains(SECRET));
    }

    @Test
    void anUnreadableKeyFileIsAnIoErrorNotAMissingKey(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("a", SECRET);
        Files.delete(dir.resolve("key.bin"));
        Files.createDirectory(dir.resolve("key.bin"));

        var e = assertThrows(UncheckedIOException.class, () -> new EncryptedLocalCredentialProvider(dir).resolve("a"));
        assertTrue(e.getMessage().contains("Failed to load local credential key"), e.getMessage());
    }

    @Test
    void failedKeyWriteIsAuditedAndAnAuditErrorDoesNotHideTheWriteError(@TempDir Path dir) throws Exception {
        List<AuditEvent.Outcome> outcomes = new ArrayList<>();
        AuditSink sink = (ctx, action, targetKind, targetId, environment, outcome, changedFields) -> {
            outcomes.add(outcome);
            if (outcome == AuditEvent.Outcome.FAILED) {
                throw new IllegalStateException("audit volume unavailable");
            }
            return null;
        };
        var provider = new EncryptedLocalCredentialProvider(dir, sink, Duration.ZERO, System::nanoTime,
                EncryptedLocalCredentialProviderDurabilityTest::failingMidway);

        var e = assertThrows(UncheckedIOException.class, () -> provider.put("a", SECRET));

        assertEquals(List.of(AuditEvent.Outcome.ATTEMPTED, AuditEvent.Outcome.FAILED), outcomes);
        assertEquals("audit volume unavailable", e.getSuppressed()[0].getMessage());
        assertFalse(Files.exists(dir.resolve("key.bin")));
    }

    @Test
    void lostKeyRaceIsAuditedAsFailedAndUsesThePublishedKey(@TempDir Path dir) throws Exception {
        List<AuditEvent.Outcome> outcomes = new ArrayList<>();
        List<byte[]> winnerKey = new ArrayList<>();
        AuditContext context = new AuditContext(AuditContext.ActorKind.SYSTEM, "job-runner", "owner-1",
                AuditContext.Source.JOB, UUID.randomUUID());
        // The sink publishes a competing key between this instance's ATTEMPTED event and its own publish.
        AuditSink sink = (ctx, action, targetKind, targetId, environment, outcome, changedFields) -> {
            outcomes.add(outcome);
            if (outcome == AuditEvent.Outcome.ATTEMPTED) {
                new EncryptedLocalCredentialProvider(dir).put("winner", "winner-secret");
                try {
                    winnerKey.add(Files.readAllBytes(dir.resolve("key.bin")));
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            return null;
        };

        new EncryptedLocalCredentialProvider(dir, sink).put(context, "loser", "loser-secret");

        assertEquals(List.of(AuditEvent.Outcome.ATTEMPTED, AuditEvent.Outcome.FAILED), outcomes);
        assertArrayEquals(winnerKey.get(0), Files.readAllBytes(dir.resolve("key.bin")));
        assertEquals("loser-secret", new EncryptedLocalCredentialProvider(dir).resolve("loser").orElseThrow());
        assertEquals(0, tmpFileCount(dir));
    }
}
