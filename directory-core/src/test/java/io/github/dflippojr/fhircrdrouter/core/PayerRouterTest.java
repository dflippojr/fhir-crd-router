package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PayerRouterTest {

    @Test
    void resolvesActiveConnection(@TempDir Path tempDir) {
        ConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));
        store.save(ConnectionRecord.builder()
                .payerId("PAYER-1").environment(Environment.PRODUCTION)
                .baseUrl("https://payer.example.test").authType(AuthType.NONE)
                .status(ConnectionStatus.ACTIVE).build());

        PayerRouter router = new PayerRouter(store);

        assertEquals("https://payer.example.test", router.resolve("PAYER-1").baseUrl());
    }

    @Test
    void refusesToResolveDeprecatedConnection(@TempDir Path tempDir) {
        ConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));
        store.save(ConnectionRecord.builder()
                .payerId("PAYER-1").environment(Environment.PRODUCTION)
                .baseUrl("https://payer.example.test").authType(AuthType.NONE)
                .status(ConnectionStatus.DEPRECATED).build());

        PayerRouter router = new PayerRouter(store);

        assertThrows(RouterException.class, () -> router.resolve("PAYER-1"));
    }

    @Test
    void unknownPayerThrows(@TempDir Path tempDir) {
        ConnectionStore store = new FileBasedConnectionStore(tempDir.resolve("connections.yaml"));
        PayerRouter router = new PayerRouter(store);

        assertThrows(RouterException.class, () -> router.resolve("NOBODY"));
    }
}
