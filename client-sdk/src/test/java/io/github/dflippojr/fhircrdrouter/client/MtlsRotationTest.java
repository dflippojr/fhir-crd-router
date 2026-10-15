package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

class MtlsRotationTest {
    @TempDir
    Path tempDir;
    private final Map<String, String> secrets = new ConcurrentHashMap<>();
    private final CredentialProvider credentials = new CredentialProvider() {
        @Override public Optional<String> resolve(String ref) { return Optional.ofNullable(secrets.get(ref)); }
        @Override public void put(String ref, String value) { secrets.put(ref, value); }
        @Override public void remove(String ref) { secrets.remove(ref); }
    };

    @Test
    void rotationsRetainOnlyCurrentClient() throws Exception {
        CdsHooksClient client = new CdsHooksClient(credentials);
        List<Integer> retained = new ArrayList<>();
        HttpClient selected = null;
        for (int i = 1; i <= 4; i++) {
            secrets.put("test-mtls", TestKeys.selfSigned(tempDir, "synthetic-" + ((i - 1) % 2)).pemBundle());
            HttpClient next = select(client, "test-mtls");
            assertNotSame(selected, next);
            selected = next;
            if (i == 1 || i == 2 || i == 4) {
                int size = client.mtlsClientCount();
                retained.add(size);
            }
        }
        assertSame(selected, select(client, "test-mtls"));
        assertSame(selected, select(client, "test-mtls"));
        assertEquals(List.of(1, 1, 1), retained);
    }

    @Test
    void referencesRotateIndependentlyAndInvalidReplacementPreservesEntry() throws Exception {
        CdsHooksClient client = new CdsHooksClient(credentials);
        String original = TestKeys.selfSigned(tempDir, "original").pemBundle();
        secrets.put("first", original);
        secrets.put("second", original);
        HttpClient first = select(client, "first");
        HttpClient second = select(client, "second");
        assertNotSame(first, second);
        assertEquals(2, client.mtlsClientCount());
        secrets.put("first", "invalid PEM");
        assertThrows(IllegalArgumentException.class, () -> select(client, "first"));
        assertEquals(2, client.mtlsClientCount());
        secrets.put("first", original);
        assertSame(first, select(client, "first"));
        assertSame(second, select(client, "second"));
        secrets.put("first", TestKeys.selfSigned(tempDir, "replacement").pemBundle());
        assertNotSame(first, select(client, "first"));
        assertSame(second, select(client, "second"));
        assertEquals(2, client.mtlsClientCount());
    }

    @Test
    void concurrentRotationPublishesOneReplacementWithConfiguredTransport() throws Exception {
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), credentials, null,
                Duration.ofSeconds(10), Duration.ofSeconds(2));
        secrets.put("test-mtls", TestKeys.selfSigned(tempDir, "original").pemBundle());
        HttpClient original = select(client, "test-mtls");
        secrets.put("test-mtls", TestKeys.selfSigned(tempDir, "replacement").pemBundle());
        var executor = Executors.newFixedThreadPool(8);
        CountDownLatch ready = new CountDownLatch(8);
        CountDownLatch start = new CountDownLatch(1);
        try {
            List<java.util.concurrent.Future<HttpClient>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(executor.submit(() -> {
                    ready.countDown();
                    assertTrue(start.await(10, TimeUnit.SECONDS));
                    return select(client, "test-mtls");
                }));
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS));
            start.countDown();
            HttpClient replacement = results.get(0).get(10, TimeUnit.SECONDS);
            assertNotSame(original, replacement);
            for (var result : results) {
                assertSame(replacement, result.get(10, TimeUnit.SECONDS));
            }
            assertEquals(Optional.of(Duration.ofSeconds(2)), replacement.connectTimeout());
            assertArrayEquals(new String[] {"TLSv1.3", "TLSv1.2"}, replacement.sslParameters().getProtocols());
            assertEquals(1, client.mtlsClientCount());
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private static HttpClient select(CdsHooksClient client, String ref) {
        var record = ConnectionRecord.builder().payerId("SYNTHETIC").environment(Environment.SANDBOX)
                .baseUrl("https://payer.invalid").authType(AuthType.NONE).mtlsCredentialRef(ref).build();
        return client.httpClientFor(record);
    }
}
