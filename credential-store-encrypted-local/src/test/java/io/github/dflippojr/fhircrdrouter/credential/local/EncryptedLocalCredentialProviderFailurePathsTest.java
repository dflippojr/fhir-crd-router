package io.github.dflippojr.fhircrdrouter.credential.local;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.UnaryOperator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Failure paths of key creation, the store lock and the secrets read (#196). Each one is forced
 * with the stream wrapper seam or by putting a directory where a file is expected, so none needs
 * POSIX permissions or root.
 */
class EncryptedLocalCredentialProviderFailurePathsTest {

    private static final String SECRET = "synthetic-secret";

    /** Records each {@code credential.key.create} outcome, in order. */
    private static final class KeyEvents {
        final List<String> outcomes = Collections.synchronizedList(new ArrayList<>());
        final AuditSink sink = (context, action, targetKind, targetId, environment, outcome, changedFields) -> {
            if (action.equals("credential.key.create")) {
                outcomes.add(outcome.name());
            }
            return null;
        };
    }

    private static EncryptedLocalCredentialProvider wrapped(Path dir, AuditSink sink,
                                                            UnaryOperator<OutputStream> outputWrapper) {
        return new EncryptedLocalCredentialProvider(dir, sink, Duration.ZERO, System::nanoTime, outputWrapper);
    }

    private static long tmpFileCount(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".tmp")).count();
        }
    }

    private static void assertMessageStarts(String prefix, Throwable error) {
        assertTrue(error.getMessage().startsWith(prefix), error.getMessage());
    }

    @Test
    void keyPublishedByAnotherWriterWhileCreatingIsTheOneUsed(@TempDir Path dir) throws IOException {
        byte[] published = new byte[32];
        for (int i = 0; i < published.length; i++) {
            published[i] = (byte) (i + 1);
        }
        AtomicBoolean first = new AtomicBoolean(true);
        // The first wrapped stream is the key.bin temp file: publish a rival key before it is written.
        UnaryOperator<OutputStream> rival = out -> {
            if (first.getAndSet(false)) {
                try {
                    Files.write(dir.resolve("key.bin"), published);
                } catch (IOException e) {
                    throw new UncheckedIOException(e);
                }
            }
            return out;
        };
        KeyEvents events = new KeyEvents();

        wrapped(dir, events.sink, rival).put("ref-1", SECRET);

        assertEquals(Optional.of(SECRET), new EncryptedLocalCredentialProvider(dir).resolve("ref-1"));
        assertArrayEquals(published, Files.readAllBytes(dir.resolve("key.bin")));
        assertEquals(List.of("ATTEMPTED", "FAILED"), events.outcomes);
        assertEquals(0, tmpFileCount(dir));
    }

    @Test
    void keyWriteFailureThrowsAndLeavesNoKeyOrTempFile(@TempDir Path dir) throws IOException {
        UnaryOperator<OutputStream> failing = out -> new FilterOutputStream(out) {
            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                throw new IOException("simulated write failure");
            }
        };
        KeyEvents events = new KeyEvents();
        var provider = wrapped(dir, events.sink, failing);

        var error = assertThrows(UncheckedIOException.class, () -> provider.put("ref-1", SECRET));

        assertMessageStarts("Failed to create local credential key", error);
        assertFalse(Files.exists(dir.resolve("key.bin")));
        assertFalse(Files.exists(dir.resolve("secrets.properties")));
        assertEquals(0, tmpFileCount(dir));
        assertEquals(List.of("ATTEMPTED", "FAILED"), events.outcomes);

        var healthy = new EncryptedLocalCredentialProvider(dir);
        healthy.put("ref-1", SECRET);
        assertEquals(Optional.of(SECRET), new EncryptedLocalCredentialProvider(dir).resolve("ref-1"));
    }

    @Test
    void lockFileThatCannotBeOpenedFailsPutAndRemoveWithoutWriting(@TempDir Path dir) throws IOException {
        new EncryptedLocalCredentialProvider(dir).put("ref-1", SECRET);
        Path lock = dir.resolve("secrets.lock");
        Files.delete(lock);
        Files.createDirectory(lock);
        byte[] secretsBefore = Files.readAllBytes(dir.resolve("secrets.properties"));
        byte[] keyBefore = Files.readAllBytes(dir.resolve("key.bin"));
        var provider = new EncryptedLocalCredentialProvider(dir);

        var putError = assertThrows(UncheckedIOException.class, () -> provider.put("ref-2", SECRET));
        var removeError = assertThrows(UncheckedIOException.class, () -> provider.remove("ref-1"));

        assertMessageStarts("Failed to lock the credential store", putError);
        assertMessageStarts("Failed to lock the credential store", removeError);
        assertArrayEquals(secretsBefore, Files.readAllBytes(dir.resolve("secrets.properties")));
        assertArrayEquals(keyBefore, Files.readAllBytes(dir.resolve("key.bin")));
        assertEquals(0, tmpFileCount(dir));
    }

    @Test
    void unreadableSecretsFileFailsResolveInsteadOfReportingNoCredential(@TempDir Path dir) throws IOException {
        Files.createDirectory(dir.resolve("secrets.properties"));
        var provider = new EncryptedLocalCredentialProvider(dir);

        var error = assertThrows(UncheckedIOException.class, () -> provider.resolve("x"));

        assertMessageStarts("Failed reading secrets file", error);
    }
}
