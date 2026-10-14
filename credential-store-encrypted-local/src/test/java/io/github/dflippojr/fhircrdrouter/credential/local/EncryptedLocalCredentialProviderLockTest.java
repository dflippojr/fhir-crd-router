package io.github.dflippojr.fhircrdrouter.credential.local;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditEvent;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** #63: writers on one directory serialize on an OS file lock, so no write is lost. */
class EncryptedLocalCredentialProviderLockTest {

    private static final int RUNS = 40;

    @Test
    void twoInstancesPuttingConcurrentlyKeepBothSecrets(@TempDir Path root) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            for (int run = 0; run < RUNS; run++) {
                Path dir = root.resolve("run-" + run);
                var a = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
                var b = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
                CountDownLatch start = new CountDownLatch(1);
                Future<?> putA = pool.submit(() -> {
                    start.await();
                    a.put("a", "secret-a");
                    return null;
                });
                Future<?> putB = pool.submit(() -> {
                    start.await();
                    b.put("b", "secret-b");
                    return null;
                });
                start.countDown();
                putA.get();
                putB.get();

                var fresh = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
                assertEquals(Optional.of("secret-a"), fresh.resolve("a"), "run " + run);
                assertEquals(Optional.of("secret-b"), fresh.resolve("b"), "run " + run);
            }
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void manyInstancesPuttingAndRemovingConcurrentlyLoseNothing(@TempDir Path dir) throws Exception {
        int writers = 4;
        int perWriter = 25;
        new EncryptedLocalCredentialProvider(dir).put("seed", "seed-secret");
        ExecutorService pool = Executors.newFixedThreadPool(writers);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> done = new ArrayList<>();
            for (int w = 0; w < writers; w++) {
                int writer = w;
                done.add(pool.submit(() -> {
                    var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
                    start.await();
                    for (int i = 0; i < perWriter; i++) {
                        provider.put("w" + writer + "-" + i, "secret-" + writer + "-" + i);
                        provider.put("temp-" + writer + "-" + i, "x");
                        provider.remove("temp-" + writer + "-" + i);
                    }
                    return null;
                }));
            }
            start.countDown();
            for (Future<?> f : done) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        var fresh = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        assertEquals(Optional.of("seed-secret"), fresh.resolve("seed"));
        for (int w = 0; w < writers; w++) {
            for (int i = 0; i < perWriter; i++) {
                assertEquals(Optional.of("secret-" + w + "-" + i), fresh.resolve("w" + w + "-" + i));
                assertEquals(Optional.empty(), fresh.resolve("temp-" + w + "-" + i));
            }
        }
    }

    @Test
    void separateProcessesPuttingConcurrentlyKeepEverySecret(@TempDir Path dir) throws Exception {
        int processes = 3;
        int perProcess = 15;
        List<Process> children = new ArrayList<>();
        for (int p = 0; p < processes; p++) {
            children.add(new ProcessBuilder(
                    Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                    "-cp", System.getProperty("java.class.path"),
                    ConcurrentPutProcess.class.getName(), dir.toString(), "p" + p, String.valueOf(perProcess))
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.DISCARD)
                    .start());
        }
        for (Process child : children) {
            assertEquals(0, child.waitFor(), "child process failed");
        }

        var fresh = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        for (int p = 0; p < processes; p++) {
            for (int i = 0; i < perProcess; i++) {
                assertEquals(Optional.of("secret-p" + p + "-" + i), fresh.resolve("p" + p + "-" + i));
            }
        }
    }

    @Test
    void theLockFileIsASidecarThatStaysAndRemoveOnAMissingStoreCreatesNothing(@TempDir Path root) throws Exception {
        Path dir = root.resolve("store");
        var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        provider.remove("absent");
        assertFalse(Files.exists(dir), "removing from a store that does not exist must not create it");

        provider.put("ref", "secret");
        assertTrue(Files.isRegularFile(dir.resolve("secrets.lock")));
        provider.remove("ref");
        assertTrue(Files.isRegularFile(dir.resolve("secrets.lock")));
        assertEquals(Optional.empty(), provider.resolve("ref"));
    }

    @Test
    void aWriteFromInsideAWriteFailsClearlyAndLeavesTheStoreUsable(@TempDir Path dir) {
        var inner = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        AuditSink reentrant = (ctx, action, targetKind, targetId, environment, outcome, changedFields) -> {
            if (outcome == AuditEvent.Outcome.ATTEMPTED) {
                inner.put("nested", "nested-secret");
            }
            return null;
        };

        var outer = new EncryptedLocalCredentialProvider(dir, reentrant, Duration.ZERO);
        IllegalStateException failure = assertThrows(IllegalStateException.class, () -> outer.put("outer", "outer-secret"));
        assertTrue(failure.getMessage().contains("already being written"), failure.getMessage());

        inner.put("after", "after-secret");
        assertEquals(Optional.of("after-secret"), inner.resolve("after"));
    }

    /** Child process for the cross-process test: an independent JVM, so an independent lock table. */
    public static final class ConcurrentPutProcess {
        public static void main(String[] args) {
            var provider = new EncryptedLocalCredentialProvider(Path.of(args[0]), null, Duration.ZERO);
            int count = Integer.parseInt(args[2]);
            for (int i = 0; i < count; i++) {
                provider.put(args[1] + "-" + i, "secret-" + args[1] + "-" + i);
            }
        }
    }
}
