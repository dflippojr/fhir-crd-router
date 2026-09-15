package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

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
}
