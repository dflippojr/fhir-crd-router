package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileBasedConnectionStoreTest {

    @Test
    void savesAndReloadsRoundTrip(@TempDir Path tempDir) {
        FileBasedConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-1")
                .displayName("Example Payer")
                .environment(Environment.SANDBOX)
                .baseUrl("https://sandbox.example-payer.test/cds")
                .authType(AuthType.API_KEY)
                .credentialRef("payer-1-sandbox-key")
                .igVersion("crd-2.0.1")
                .build();

        store.save(record);

        // A fresh store instance over the same file to prove it actually persisted.
        FileBasedConnectionStore reloaded = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));
        List<ConnectionRecord> all = reloaded.findAll();

        assertEquals(1, all.size());
        assertEquals("PAYER-1", all.get(0).payerId());
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
}
