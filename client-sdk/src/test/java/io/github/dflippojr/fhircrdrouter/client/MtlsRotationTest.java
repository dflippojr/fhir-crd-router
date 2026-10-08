package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.lang.reflect.InvocationTargetException;
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
    void tenRotationsRetainOnlyCurrentClient() throws Exception {
        CdsHooksClient client = new CdsHooksClient(credentials);
        long baseline = selectorThreads();
        List<Integer> retained = new ArrayList<>();
        HttpClient selected = null;
        for (int i = 1; i <= 10; i++) {
            secrets.put("test-mtls", TestKeys.selfSigned(tempDir, "synthetic-" + i).pemBundle());
            HttpClient next = select(client, "test-mtls");
            assertNotSame(selected, next);
            selected = next;
            if (i == 1 || i == 5 || i == 10) {
                int size = cache(client).size();
                retained.add(size);
                System.out.printf("mTLS measurement: versions=%d retained=%d addedSelectorThreads=%d%n",
                        i, size, selectorThreads() - baseline);
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
        Map<?, ?> before = Map.copyOf(cache(client));
        secrets.put("first", "invalid PEM");
        assertThrows(IllegalArgumentException.class, () -> select(client, "first"));
        assertEquals(before, cache(client));
        secrets.put("first", original);
        assertSame(first, select(client, "first"));
        secrets.put("first", TestKeys.selfSigned(tempDir, "replacement").pemBundle());
        assertNotSame(first, select(client, "first"));
        assertSame(second, select(client, "second"));
        assertEquals(2, cache(client).size());
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
            assertEquals(1, cache(client).size());
        } finally {
            start.countDown();
            executor.shutdownNow();
        }
    }

    private static long selectorThreads() {
        return Thread.getAllStackTraces().keySet().stream()
                .filter(thread -> thread.getName().contains("SelectorManager")).count();
    }

    private static Map<?, ?> cache(CdsHooksClient client) throws Exception {
        var field = CdsHooksClient.class.getDeclaredField("mtlsClients");
        field.setAccessible(true);
        return (Map<?, ?>) field.get(client);
    }

    private static HttpClient select(CdsHooksClient client, String ref) throws Exception {
        var method = CdsHooksClient.class.getDeclaredMethod("httpClientFor", ConnectionRecord.class);
        method.setAccessible(true);
        var record = ConnectionRecord.builder().payerId("SYNTHETIC").environment(Environment.SANDBOX)
                .baseUrl("https://payer.invalid").authType(AuthType.NONE).mtlsCredentialRef(ref).build();
        try {
            return (HttpClient) method.invoke(client, record);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException cause) {
                throw cause;
            }
            throw e;
        }
    }
}
