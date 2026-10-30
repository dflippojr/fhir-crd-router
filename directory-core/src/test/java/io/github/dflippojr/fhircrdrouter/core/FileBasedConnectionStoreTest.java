package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledOnOs;
import org.junit.jupiter.api.condition.OS;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.dflippojr.fhircrdrouter.core.internal.AtomicFiles;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class FileBasedConnectionStoreTest {

    @Test
    void savesAndReloadsRoundTrip(@TempDir Path tempDir) {
        FileBasedConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-1")
                .displayName("Example Payer")
                .environment(Environment.SANDBOX)
                .baseUrl("https://sandbox.example-payer.test/cds")
                .authType(AuthType.CDS_HOOKS_JWT)
                .clientId("https://ehr.test/cds-client")
                .keyId("key-2026-09")
                .jwksUrl("https://ehr.test/.well-known/jwks.json")
                .tenant("clinic-7")
                .credentialRef("payer-1-sandbox-key")
                .mtlsCredentialRef("client-cert")
                .igVersion("crd-2.0.1")
                .build();

        store.save(record);

        // A fresh store instance over the same file to prove it actually persisted.
        FileBasedConnectionStore reloaded = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));
        List<ConnectionRecord> all = reloaded.findAll();

        assertEquals(1, all.size());
        ConnectionRecord loaded = all.get(0);
        assertEquals("PAYER-1", loaded.payerId());
        assertEquals(AuthType.CDS_HOOKS_JWT, loaded.authType());
        assertEquals("https://ehr.test/cds-client", loaded.clientId());
        assertEquals("key-2026-09", loaded.keyId());
        assertEquals("https://ehr.test/.well-known/jwks.json", loaded.jwksUrl());
        assertEquals("clinic-7", loaded.tenant());
        assertEquals("payer-1-sandbox-key", loaded.credentialRef());
        assertEquals("client-cert", loaded.mtlsCredentialRef());
        assertTrue(reloaded.findByPayerIdAndEnvironment("PAYER-1", Environment.SANDBOX).isPresent());
        assertTrue(reloaded.findByPayerIdAndEnvironment("PAYER-1", Environment.PRODUCTION).isEmpty());
    }

    @Test
    void deleteRemovesOnlyMatchingEnvironment(@TempDir Path tempDir) {
        FileBasedConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));

        store.save(ConnectionRecord.builder()
                .payerId("PAYER-2").environment(Environment.SANDBOX)
                .baseUrl("https://sandbox.example.test").authType(AuthType.NONE).build());
        store.save(ConnectionRecord.builder()
                .payerId("PAYER-2").environment(Environment.PRODUCTION)
                .baseUrl("https://prod.example.test").authType(AuthType.NONE).build());

        store.delete("PAYER-2", Environment.SANDBOX);

        assertTrue(store.findByPayerIdAndEnvironment("PAYER-2", Environment.SANDBOX).isEmpty());
        assertTrue(store.findByPayerIdAndEnvironment("PAYER-2", Environment.PRODUCTION).isPresent());
    }

    @Test
    void deleteOnAMissingFileCreatesNothing(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");

        new FileBasedConnectionStore(file).delete("X", Environment.SANDBOX);

        assertTrue(Files.notExists(file));
        assertEquals(0, tmpFileCount(tempDir));
    }

    @Test
    void deleteOfAnAbsentRecordDoesNotRewrite(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("A"));
        byte[] before = Files.readAllBytes(file);
        AtomicInteger moves = new AtomicInteger();
        FileBasedConnectionStore store = storeWithMover(file, refusing(0, moves));

        store.delete("B", Environment.SANDBOX);

        assertEquals(0, moves.get());
        assertArrayEquals(before, Files.readAllBytes(file));
        assertEquals(0, tmpFileCount(tempDir));
    }

    private static ConnectionRecord record(String payerId) {
        return ConnectionRecord.builder()
                .payerId(payerId).environment(Environment.SANDBOX)
                .baseUrl("https://" + payerId + ".example.test").authType(AuthType.NONE).build();
    }

    private static long tmpFileCount(Path dir) throws IOException {
        try (Stream<Path> files = Files.list(dir)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".tmp")).count();
        }
    }

    @Test
    void failureDuringWriteKeepsPreviousFileAndCleansUpTempFile(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("KEEP-ME"));
        String before = Files.readString(file);

        ObjectMapper failing = new ObjectMapper() {
            @Override
            public void writeValue(OutputStream out, Object value) throws IOException {
                out.write("partial: [".getBytes());
                throw new IOException("simulated disk full");
            }
        };
        FileBasedConnectionStore broken = new FileBasedConnectionStore(file, failing);

        assertThrows(UncheckedIOException.class, () -> broken.save(record("NEW")));

        assertEquals(before, Files.readString(file));
        assertEquals(1, new FileBasedConnectionStore(file).findAll().size());
        assertEquals(0, tmpFileCount(tempDir));
    }

    @Test
    void concurrentSavesFromManyThreadsLoseNoRecords(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        int n = 20;
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<?>> futures = new ArrayList<>();
            for (int i = 0; i < n; i++) {
                String id = "PAYER-" + i;
                futures.add(pool.submit(() -> store.save(record(id))));
            }
            for (Future<?> f : futures) {
                f.get();
            }
        } finally {
            pool.shutdownNow();
        }

        assertEquals(n, new FileBasedConnectionStore(file).findAll().size());
        assertEquals(0, tmpFileCount(tempDir));
    }

    /** A move that is refused {@code refusals} times, as Windows refuses it while a reader has the file open. */
    private static AtomicFiles.Mover refusing(int refusals, AtomicInteger attempts) {
        return (tmp, target) -> {
            if (attempts.incrementAndGet() <= refusals) {
                throw new AccessDeniedException(tmp + " -> " + target);
            }
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        };
    }

    private static FileBasedConnectionStore storeWithMover(Path file, AtomicFiles.Mover mover) {
        return new FileBasedConnectionStore(file, new CountingMapper(), mover);
    }

    @Test
    void refusedReplaceIsRetriedUntilItSucceeds(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("KEEP-ME"));
        AtomicInteger attempts = new AtomicInteger();

        storeWithMover(file, refusing(3, attempts)).save(record("NEW"));

        assertEquals(4, attempts.get());
        assertEquals(2, new FileBasedConnectionStore(file).findAll().size());
        assertEquals(0, tmpFileCount(tempDir));
    }

    @Test
    void replaceRefusedPastTheRetryBudgetFailsAndKeepsTheFile(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("KEEP-ME"));
        String before = Files.readString(file);
        AtomicInteger attempts = new AtomicInteger();
        FileBasedConnectionStore store = storeWithMover(file, refusing(Integer.MAX_VALUE, attempts));

        UncheckedIOException e = assertThrows(UncheckedIOException.class,
                () -> store.delete("KEEP-ME", Environment.SANDBOX));

        assertInstanceOf(AccessDeniedException.class, e.getCause());
        assertTrue(e.getMessage().contains("open in another process"), e.getMessage());
        assertEquals(25, attempts.get());
        assertEquals(before, Files.readString(file));
        assertEquals(0, tmpFileCount(tempDir));
    }

    @Test
    void interruptStopsRetryingARefusedReplace(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("KEEP-ME"));
        AtomicInteger attempts = new AtomicInteger();
        FileBasedConnectionStore store = storeWithMover(file, (tmp, target) -> {
            attempts.incrementAndGet();
            Thread.currentThread().interrupt();
            throw new AccessDeniedException(tmp + " -> " + target);
        });

        try {
            UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> store.save(record("NEW")));

            assertInstanceOf(AccessDeniedException.class, e.getCause());
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        assertEquals(1, attempts.get());
        assertEquals(0, tmpFileCount(tempDir));
        assertTrue(new FileBasedConnectionStore(file).findByPayerId("NEW").isEmpty());
    }

    @Test
    void failedReplaceKeepsOldFileAndRemovesTemp(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(record("KEEP-ME"));
        byte[] before = Files.readAllBytes(file);
        CountingMapper mapper = new CountingMapper();
        FileBasedConnectionStore store = new FileBasedConnectionStore(file, mapper, (tmp, target) -> {
            throw new IOException("synthetic disk full");
        });
        ConnectionRecord kept = store.findByPayerIdAndEnvironment("KEEP-ME", Environment.SANDBOX).orElseThrow();
        int parses = mapper.parses.get();

        UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> store.save(record("NEW")));

        assertTrue(e.getMessage().startsWith("Failed writing connection store at"), e.getMessage());
        assertEquals("synthetic disk full", e.getCause().getMessage());
        assertArrayEquals(before, Files.readAllBytes(file));
        try (Stream<Path> files = Files.list(tempDir)) {
            assertEquals(List.of(file), files.toList());
        }
        assertEquals(List.of(kept), store.findAll());
        assertEquals(kept, store.findByPayerIdAndEnvironment("KEEP-ME", Environment.SANDBOX).orElseThrow());
        assertEquals(parses, mapper.parses.get(), "the cache still holds the old file's records");
    }

    /**
     * Opens {@code file} for reading on another thread, as a second process's read would, and
     * closes it after {@code millis}. Returns once the handle is open.
     */
    private static Future<?> holdOpen(ExecutorService pool, Path file, long millis) throws InterruptedException {
        CountDownLatch opened = new CountDownLatch(1);
        Future<?> holder = pool.submit(() -> {
            try (InputStream in = Files.newInputStream(file)) {
                opened.countDown();
                Thread.sleep(millis);
            }
            return null;
        });
        opened.await();
        return holder;
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void saveWaitsForAShortLivedReaderToCloseTheFile(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        store.save(record("KEEP-ME"));
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> holder = holdOpen(pool, file, 100);

            store.save(record("NEW"));

            holder.get();
        } finally {
            pool.shutdownNow();
        }

        assertEquals(2, new FileBasedConnectionStore(file).findAll().size());
        assertEquals(0, tmpFileCount(tempDir));
    }

    @Test
    @EnabledOnOs(OS.WINDOWS)
    void saveFailsWhenAReaderKeepsTheFileOpenPastTheRetryBudget(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        store.save(record("KEEP-ME"));
        String before = Files.readString(file);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> holder = holdOpen(pool, file, 2_000);

            UncheckedIOException e = assertThrows(UncheckedIOException.class, () -> store.save(record("NEW")));

            assertInstanceOf(AccessDeniedException.class, e.getCause());
            assertTrue(e.getMessage().contains("open in another process"), e.getMessage());
            holder.get();
        } finally {
            pool.shutdownNow();
        }

        assertEquals(before, Files.readString(file));
        assertEquals(0, tmpFileCount(tempDir));
    }

    /** A YAML mapper like the store's default that counts deserializations. */
    private static final class CountingMapper extends ObjectMapper {
        final AtomicInteger parses = new AtomicInteger();

        CountingMapper() {
            super(new YAMLFactory());
            registerModule(new JavaTimeModule());
            disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
            enable(SerializationFeature.INDENT_OUTPUT);
        }

        @Override
        public <T> T readValue(byte[] src, Class<T> valueType) throws IOException {
            parses.incrementAndGet();
            return super.readValue(src, valueType);
        }
    }

    @Test
    void unchangedFileIsParsedAtMostOnce(@TempDir Path tempDir) {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore writer = new FileBasedConnectionStore(file);
        for (int i = 0; i < 100; i++) {
            writer.save(record("PAYER-" + i));
        }
        CountingMapper mapper = new CountingMapper();
        FileBasedConnectionStore store = new FileBasedConnectionStore(file, mapper);

        for (int i = 0; i < 100; i++) {
            assertTrue(store.findByPayerIdAndEnvironment("PAYER-99", Environment.SANDBOX).isPresent());
        }

        assertEquals(1, mapper.parses.get());
    }

    @Test
    void saveAndDeleteRefreshTheCacheWithoutParsing(@TempDir Path tempDir) {
        CountingMapper mapper = new CountingMapper();
        FileBasedConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"), mapper);

        store.save(record("A"));
        int afterFirstSave = mapper.parses.get();
        assertEquals(List.of("A"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
        assertEquals(afterFirstSave, mapper.parses.get());

        store.save(record("B"));
        int afterSecondSave = mapper.parses.get();
        assertEquals(List.of("A", "B"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
        assertEquals(afterSecondSave, mapper.parses.get());

        store.delete("A", Environment.SANDBOX);
        assertEquals(List.of("B"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
        assertEquals(afterSecondSave, mapper.parses.get());
    }

    @Test
    void externalSameLengthEditIsSeenOnNextRead(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        store.save(record("PAYER-A"));
        List<ConnectionRecord> first = store.findAll();
        assertSame(first, store.findAll());

        String original = Files.readString(file);
        String edited = original.replace("PAYER-A", "PAYER-B");
        assertEquals(original.length(), edited.length());
        FileTime mtime = Files.getLastModifiedTime(file);
        Files.writeString(file, edited);
        Files.setLastModifiedTime(file, mtime);

        assertTrue(store.findByPayerIdAndEnvironment("PAYER-A", Environment.SANDBOX).isEmpty());
        assertTrue(store.findByPayerIdAndEnvironment("PAYER-B", Environment.SANDBOX).isPresent());
    }

    @Test
    void externallyDeletedFileYieldsEmptyList(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        store.save(record("PAYER-A"));
        assertEquals(1, store.findAll().size());

        Files.delete(file);

        assertTrue(store.findAll().isEmpty());
        assertTrue(store.findByPayerId("PAYER-A").isEmpty());
    }

    @Test
    void externallyCorruptedFileThrowsInsteadOfServingCache(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        store.save(record("PAYER-A"));
        assertEquals(1, store.findAll().size());

        Files.writeString(file, "- payerId: [unterminated\n");

        assertThrows(UncheckedIOException.class, store::findAll);
        assertThrows(UncheckedIOException.class,
                () -> store.findByPayerIdAndEnvironment("PAYER-A", Environment.SANDBOX));
    }

    /**
     * #156 enforces the https rule in the client SDK, not here: a stored record with an http or malformed
     * URL still loads, so one old record cannot break {@code resolve} for every other payer.
     */
    @Test
    void recordsWithHttpOrMalformedUrlsStillLoad(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-HTTP"
                  environment: "PRODUCTION"
                  baseUrl: "http://payer.example/r4"
                  authType: "OAUTH2_CLIENT_CREDENTIALS"
                  tokenEndpoint: "http://auth.example/token"
                  clientId: "client"
                  jwksUrl: "http://ehr.example/jwks.json"
                - payerId: "PAYER-MALFORMED"
                  environment: "PRODUCTION"
                  baseUrl: "https://payer example/r4"
                  authType: "NONE"
                - payerId: "PAYER-OK"
                  environment: "PRODUCTION"
                  baseUrl: "https://ok.example/r4"
                  authType: "NONE"
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(3, store.findAll().size());
        assertEquals("http://payer.example/r4",
                new PayerRouter(store).resolve("PAYER-HTTP", Environment.PRODUCTION).baseUrl());
        assertEquals("https://ok.example/r4", new PayerRouter(store).resolve("PAYER-OK", Environment.PRODUCTION).baseUrl());
    }

    /**
     * #193: every YAML document that holds no records reads as an empty store, the same as a missing
     * file, and {@code save} can write the first record into it. The cases cover the class, not one
     * instance: no bytes, whitespace only, comments only, a bare document marker, and the explicit
     * empty values {@code null}, {@code ~} and {@code []} that already worked.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "",
            " ",
            "\n\n",
            "\t \r\n  \n",
            "# no records yet\n",
            "# no records yet",
            "  # indented comment\n\n# another\n",
            "---\n",
            "--- # empty document\n",
            "---\n...\n",
            "null\n",
            "~\n",
            "[]\n",
            "# leading comment\n[]\n",
    })
    void documentWithNoRecordsReadsAsEmptyAndAcceptsTheFirstSave(String content, @TempDir Path tempDir)
            throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        Files.writeString(file, content);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(List.of(), store.findAll());
        assertEquals(List.of(), store.findByPayerId("PAYER-A"));
        assertTrue(store.findByPayerIdAndEnvironment("PAYER-A", Environment.SANDBOX).isEmpty());
        // Through the router an empty store is "no connection", not a store failure.
        assertThrows(RouterException.class, () -> new PayerRouter(store).resolve("PAYER-A", Environment.SANDBOX));
        store.delete("PAYER-A", Environment.SANDBOX);
        assertEquals(content, Files.readString(file));

        store.save(record("PAYER-A"));

        List<ConnectionRecord> reloaded = new FileBasedConnectionStore(file).findAll();
        assertEquals(List.of("PAYER-A"), reloaded.stream().map(ConnectionRecord::payerId).toList());
    }

    /**
     * #193: reading an empty document as no records must not widen into reading a broken one as no
     * records. Each of these is malformed YAML or not a list of records, and must still fail.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "- payerId: [\n",
            "- payerId: [unterminated\n",
            "# comment first\n- payerId: [\n",
            "\"unterminated\n",
            "payerId: PAYER-A\n",
            "just a string\n",
            "--- [\n",
    })
    void malformedOrNonListDocumentStillThrows(String content, @TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        Files.writeString(file, content);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertThrows(UncheckedIOException.class, store::findAll);
        assertThrows(UncheckedIOException.class, () -> store.save(record("PAYER-A")));
        assertEquals(content, Files.readString(file));
    }

    @Test
    void emptyFileIsParsedAtMostOnceWhileUnchanged(@TempDir Path tempDir) throws Exception {
        Path file = tempDir.resolve("connections.yaml");
        Files.writeString(file, "# no records yet\n");
        CountingMapper mapper = new CountingMapper();
        FileBasedConnectionStore store = new FileBasedConnectionStore(file, mapper);

        List<ConnectionRecord> first = store.findAll();
        for (int i = 0; i < 10; i++) {
            assertSame(first, store.findAll());
        }

        assertTrue(mapper.parses.get() <= 1);
    }
}
