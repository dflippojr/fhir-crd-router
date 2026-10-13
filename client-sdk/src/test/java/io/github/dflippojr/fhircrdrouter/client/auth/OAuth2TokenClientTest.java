package io.github.dflippojr.fhircrdrouter.client.auth;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class OAuth2TokenClientTest {

    private HttpServer server;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicReference<String> expiresInJson = new AtomicReference<>(",\"expires_in\":300");
    private final AtomicReference<String> lastAuthorization = new AtomicReference<>();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private final AtomicBoolean tokenEndpointFails = new AtomicBoolean();
    private volatile long tokenDelayMillis;
    private OAuth2TokenClient tokenClient;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        server.createContext("/token", exchange -> {
            int n = tokenRequests.incrementAndGet();
            if (tokenDelayMillis > 0) {
                try {
                    Thread.sleep(tokenDelayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            if (tokenEndpointFails.get()) {
                exchange.sendResponseHeaders(500, -1);
                exchange.close();
                return;
            }
            lastAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            TestResponses.respond(exchange, 200,
                    "{\"access_token\":\"token-" + n + "\",\"token_type\":\"Bearer\"" + expiresInJson.get() + "}");
        });
        server.start();
        tokenClient = new OAuth2TokenClient(HttpClient.newHttpClient(), clock);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void reusesTokenUntilJustBeforeExpiry() {
        ConnectionRecord record = record(List.of("crd"));

        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
        clock.advance(Duration.ofSeconds(300).minus(OAuth2TokenClient.EXPIRY_SKEW).minusSeconds(1));
        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));

        clock.advance(Duration.ofSeconds(1));
        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void secretSupplierRunsOnlyWhenTokenRequestIsSent() {
        ConnectionRecord record = record(List.of());
        AtomicInteger lookups = new AtomicInteger();
        Supplier<String> secret = () -> {
            lookups.incrementAndGet();
            return "secret";
        };
        HttpClient http = HttpClient.newHttpClient();

        assertEquals("token-1", tokenClient.fetchAccessToken(http, record, secret, 1));
        assertEquals("token-1", tokenClient.fetchAccessToken(http, record, secret, 1));
        assertEquals(1, lookups.get());

        tokenClient.invalidate(record);
        assertEquals("token-2", tokenClient.fetchAccessToken(http, record, secret, 2));
        assertEquals(2, lookups.get());
    }

    @Test
    void secretSupplierFailureReachesWaitersAndIsNotCached() throws Exception {
        ConnectionRecord record = record(List.of());
        CountDownLatch leaderInSupplier = new CountDownLatch(1);
        CountDownLatch releaseLeader = new CountDownLatch(1);
        AtomicInteger lookups = new AtomicInteger();
        RouterException missing = new RouterException("synthetic missing secret");
        Supplier<String> failing = () -> {
            lookups.incrementAndGet();
            leaderInSupplier.countDown();
            try {
                if (!releaseLeader.await(10, TimeUnit.SECONDS)) {
                    throw new IllegalStateException("leader was never released");
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            throw missing;
        };
        HttpClient http = HttpClient.newHttpClient();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<Throwable> leader = pool.submit(() ->
                    assertThrows(RouterException.class, () -> tokenClient.fetchAccessToken(http, record, failing, 1)));
            assertTrue(leaderInSupplier.await(10, TimeUnit.SECONDS));
            AtomicReference<Thread> waiterThread = new AtomicReference<>();
            Future<Throwable> waiter = pool.submit(() -> {
                waiterThread.set(Thread.currentThread());
                return assertThrows(RouterException.class, () -> tokenClient.fetchAccessToken(http, record, failing, 1));
            });
            // The waiter parks on the leader's flight; it must not run the supplier itself.
            while (waiterThread.get() == null || waiterThread.get().getState() != Thread.State.WAITING) {
                Thread.sleep(5);
            }
            releaseLeader.countDown();
            assertSame(missing, leader.get(10, TimeUnit.SECONDS));
            assertSame(missing, waiter.get(10, TimeUnit.SECONDS));
        } finally {
            releaseLeader.countDown();
            pool.shutdownNow();
        }
        assertEquals(1, lookups.get());
        assertEquals(0, tokenRequests.get());

        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
    }

    @Test
    void doesNotCacheTokenWithoutExpiresIn() {
        expiresInJson.set("");
        ConnectionRecord record = record(List.of());

        tokenClient.fetchAccessToken(record, "secret");
        tokenClient.fetchAccessToken(record, "secret");

        assertEquals(2, tokenRequests.get());
    }

    @Test
    void invalidateForcesRefetch() {
        ConnectionRecord record = record(List.of());

        tokenClient.fetchAccessToken(record, "secret");
        tokenClient.invalidate(record);

        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
    }

    @Test
    void cachesSeparatelyPerClientIdAndScopes() {
        String a = tokenClient.fetchAccessToken(record("client-a", List.of("crd")), "secret");
        String b = tokenClient.fetchAccessToken(record("client-b", List.of("crd")), "secret");
        String c = tokenClient.fetchAccessToken(record("client-a", List.of("other")), "secret");

        assertNotEquals(a, b);
        assertNotEquals(a, c);
        assertEquals(3, tokenRequests.get());
    }

    @Test
    void sendsFormEncodedClientSecretBasicCredentials() {
        tokenClient.fetchAccessToken(record("client id", List.of()), "p@ss:word");

        String decoded = new String(Base64.getDecoder().decode(lastAuthorization.get().substring("Basic ".length())),
                StandardCharsets.UTF_8);
        assertEquals("client+id:p%40ss%3Aword", decoded);
    }

    @Test
    void recordRequiresClientIdForOAuth2() {
        assertThrows(IllegalArgumentException.class, () -> record(null, List.of()));
    }

    @Test
    void concurrentColdCallersShareOneTokenRequest() throws Exception {
        tokenDelayMillis = 50;
        ConnectionRecord record = record(List.of());

        List<String> tokens = concurrently(32, () -> tokenClient.fetchAccessToken(record, "secret"));

        assertEquals(1, tokenRequests.get());
        assertEquals(32, tokens.size());
        tokens.forEach(t -> assertEquals("token-1", t));
    }

    @Test
    void concurrentColdCallersShareOneSignedAssertionRequest() throws Exception {
        tokenDelayMillis = 50;
        String pem = TestKeys.privateKeyPem(TestKeys.rsa(2048));
        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-PKJWT")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort())
                .authType(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                .tokenEndpoint("http://localhost:" + server.getAddress().getPort() + "/token")
                .clientId("client")
                .keyId("key-1")
                .credentialRef("ref")
                .build();

        List<String> tokens = concurrently(8, () -> tokenClient.fetchAccessToken(record, pem));

        assertEquals(1, tokenRequests.get());
        tokens.forEach(t -> assertEquals("token-1", t));
    }

    @Test
    void failureReachesEveryWaiterAndIsNotCached() throws Exception {
        tokenDelayMillis = 50;
        tokenEndpointFails.set(true);
        ConnectionRecord record = record(List.of());
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<Throwable>> results = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> {
                    start.await();
                    return assertThrows(PayerCallException.class, () -> tokenClient.fetchAccessToken(record, "secret"));
                }));
            }
            start.countDown();
            Throwable first = results.get(0).get(10, TimeUnit.SECONDS);
            for (Future<Throwable> r : results) {
                assertSame(first, r.get(10, TimeUnit.SECONDS));
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, tokenRequests.get());

        tokenEndpointFails.set(false);
        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void invalidateDuringFlightLetsNextCallerStartFreshRequest() throws Exception {
        tokenDelayMillis = 200;
        ConnectionRecord record = record(List.of());
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<String> old = pool.submit(() -> tokenClient.fetchAccessToken(record, "secret"));
            while (tokenRequests.get() == 0) {
                Thread.sleep(5);
            }
            tokenClient.invalidate(record);
            String fresh = tokenClient.fetchAccessToken(record, "secret");
            assertEquals("token-1", old.get(10, TimeUnit.SECONDS));
            assertEquals("token-2", fresh);
            assertEquals(2, tokenRequests.get());
        } finally {
            pool.shutdownNow();
        }
    }

    private static List<String> concurrently(int threads, Supplier<String> call) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<String>> futures = new ArrayList<>();
            for (int i = 0; i < threads; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return call.get();
                }));
            }
            start.countDown();
            List<String> results = new ArrayList<>();
            for (Future<String> f : futures) {
                results.add(f.get(10, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdownNow();
        }
    }

    private ConnectionRecord record(List<String> scopes) {
        return record("client", scopes);
    }

    private ConnectionRecord record(String clientId, List<String> scopes) {
        return ConnectionRecord.builder()
                .payerId("PAYER-OAUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort())
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("http://localhost:" + server.getAddress().getPort() + "/token")
                .clientId(clientId)
                .scopes(scopes)
                .credentialRef("ref")
                .build();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override public Instant instant() { return now; }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    }
}
