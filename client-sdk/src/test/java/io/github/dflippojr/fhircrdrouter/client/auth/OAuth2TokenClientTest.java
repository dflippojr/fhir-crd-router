package io.github.dflippojr.fhircrdrouter.client.auth;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.FailingHttpClient;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.client.EndpointUrlException;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.net.http.HttpClient.Redirect;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

class OAuth2TokenClientTest {

    private HttpServer server;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger redirects = new AtomicInteger();
    private final AtomicReference<String> expiresInJson = new AtomicReference<>(",\"expires_in\":300");
    private final AtomicReference<String> accessTokenJson = new AtomicReference<>();
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
                    "{\"access_token\":" + (accessTokenJson.get() != null ? accessTokenJson.get() : "\"token-" + n + "\"")
                            + ",\"token_type\":\"Bearer\"" + expiresInJson.get() + "}");
        });
        server.createContext("/moved", exchange -> {
            redirects.incrementAndGet();
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Location", "/token");
            exchange.sendResponseHeaders(307, -1);
            exchange.close();
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
    void cleartextTokenEndpointIsRefusedBeforeTheSecretIsRead() {
        ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-156").environment(Environment.SANDBOX)
                .baseUrl("https://payer.example").authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("http://auth.example/token").clientId("client").credentialRef("ref").build();

        EndpointUrlException e = assertThrows(EndpointUrlException.class,
                () -> tokenClient.fetchAccessToken(HttpClient.newHttpClient(), record,
                        () -> fail("secret read for a refused token endpoint"), 1));

        assertEquals("tokenEndpoint", e.field());
        assertEquals(0, tokenRequests.get());
    }

    /**
     * A client that follows redirects would resend the secret or assertion to wherever the token endpoint
     * points it, unchecked, e.g. from https to http (#156). It is refused before the secret is read.
     */
    @ParameterizedTest
    @EnumSource(value = Redirect.class, names = {"NORMAL", "ALWAYS"})
    void redirectFollowingClientIsRefusedBeforeTheSecretIsRead(Redirect policy) {
        ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-OAUTH").environment(Environment.SANDBOX)
                .baseUrl(origin()).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(origin() + "/moved").clientId("client").credentialRef("ref").build();
        HttpClient http = HttpClient.newBuilder().followRedirects(policy).build();

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> tokenClient.fetchAccessToken(http, record, () -> fail("secret read for a redirecting client"), 1));

        assertTrue(e.getMessage().contains("redirect"), e.getMessage());
        assertEquals(0, redirects.get());
        assertEquals(0, tokenRequests.get());
    }

    @Test
    void redirectFollowingClientIsRefusedEvenWithACachedToken() {
        ConnectionRecord record = record(List.of());
        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));

        assertThrows(IllegalArgumentException.class, () -> tokenClient.fetchAccessToken(
                new FailingHttpClient(Redirect.ALWAYS), record, () -> fail("secret read"), 1));
        assertEquals(1, tokenRequests.get());
    }

    @ParameterizedTest
    @EnumSource(value = Redirect.class, names = {"NORMAL", "ALWAYS"})
    void constructorRefusesRedirectFollowingClient(Redirect policy) {
        HttpClient http = new FailingHttpClient(policy);

        assertThrows(IllegalArgumentException.class, () -> new OAuth2TokenClient(http));
        assertThrows(IllegalArgumentException.class, () -> new OAuth2TokenClient(http, clock));
    }

    /** The assertion's jku is checked before the private key is read or any request is built (#156). */
    @ParameterizedTest
    @ValueSource(strings = {"http://ehr.example/jwks.json", "/jwks.json", "https://ehr example/jwks.json",
            "ftp://ehr.example/jwks.json", "https:///jwks.json"})
    void refusedJwksUrlIsCheckedBeforeTheSecretIsRead(String jwksUrl) {
        OAuth2TokenClient client = new OAuth2TokenClient(new FailingHttpClient(), clock);

        EndpointUrlException e = assertThrows(EndpointUrlException.class, () -> client.fetchAccessToken(
                new FailingHttpClient(), privateKeyJwtRecord(jwksUrl),
                () -> { throw new IllegalStateException("credential provider down"); }, 1));

        assertEquals("jwksUrl", e.field());
        assertEquals("PAYER-PKJWT", e.payerId());
    }

    /** jwksUrl is not part of the cache key, so a cached token must not skip its check. */
    @Test
    void refusedJwksUrlIsCheckedBeforeACachedTokenIsReturned() {
        String pem = TestKeys.privateKeyPem(TestKeys.rsa2048());
        assertEquals("token-1", tokenClient.fetchAccessToken(privateKeyJwtRecord("https://ehr.example/jwks.json"), pem));

        EndpointUrlException e = assertThrows(EndpointUrlException.class,
                () -> tokenClient.fetchAccessToken(privateKeyJwtRecord("http://ehr.example/jwks.json"), pem));

        assertEquals("jwksUrl", e.field());
        assertEquals(1, tokenRequests.get());
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
            awaitUntil(() -> waiterThread.get() != null && waiterThread.get().getState() == Thread.State.WAITING,
                    "waiter never parked on the leader's flight");
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
    void hugeExpiresInIsCappedInsteadOfOverflowing() {
        ConnectionRecord record = record(List.of());
        for (String huge : List.of("99999999999999999", String.valueOf(Long.MAX_VALUE))) {
            expiresInJson.set(",\"expires_in\":" + huge);
            tokenClient.invalidate(record);
            tokenRequests.set(0);

            assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
            clock.advance(OAuth2TokenClient.MAX_CACHE_LIFETIME.minus(OAuth2TokenClient.EXPIRY_SKEW).minusSeconds(1));
            assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));

            clock.advance(Duration.ofSeconds(1));
            assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
            assertEquals(2, tokenRequests.get());
        }
    }

    @Test
    void numericStringExpiresInIsCached() {
        ConnectionRecord record = record(List.of());
        // RFC 6749 §5.1 says a number, but some servers (older Azure AD endpoints) send a string (#105).
        for (String text : List.of("\"3600\"", "\"3600 \"", "\" 3600\"")) {
            expiresInJson.set(",\"expires_in\":" + text);
            tokenClient.invalidate(record);
            tokenRequests.set(0);

            assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"), text);
            clock.advance(Duration.ofSeconds(3600).minus(OAuth2TokenClient.EXPIRY_SKEW).minusSeconds(1));
            assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"), text);
            assertEquals(1, tokenRequests.get(), "a cached token makes no token request for " + text);

            clock.advance(Duration.ofSeconds(1));
            assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"), text);
            assertEquals(2, tokenRequests.get(), text);
        }
    }

    @Test
    void hugeNumericStringExpiresInIsCapped() {
        expiresInJson.set(",\"expires_in\":\"99999999999999\"");
        ConnectionRecord record = record(List.of());

        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
        clock.advance(OAuth2TokenClient.MAX_CACHE_LIFETIME.minus(OAuth2TokenClient.EXPIRY_SKEW).minusSeconds(1));
        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));

        clock.advance(Duration.ofSeconds(1));
        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void unusableExpiresInIsNotCachedAndDoesNotThrow() {
        ConnectionRecord record = record(List.of());
        for (String bad : List.of("\"abc\"", "\"\"", "\"  \"", "\"-1\"", "\"0\"", "\"1.5\"", "\"1e3\"",
                "\"99999999999999999999\"", "-1", "0", "null", "true", "{}", "[]")) {
            expiresInJson.set(",\"expires_in\":" + bad);
            tokenClient.invalidate(record);
            tokenRequests.set(0);

            assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"), bad);
            assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"), bad);
            assertEquals(2, tokenRequests.get(), "nothing may be cached for " + bad);
        }
    }

    @Test
    void unusableAccessTokenIsRejectedAndNeverCached() {
        ConnectionRecord record = record(List.of());
        // The last six are text but not RFC 6750 b64token: non-BMP, CRLF, NUL, space, Latin-1, leading "=" (#111).
        for (String bad : List.of("null", "\"\"", "\"  \"", "{}", "[]", "123", "true",
                "\"𐀀\"", "\"tok\\r\\n\"", "\"tok\\u0000\"", "\"a b\"", "\"café\"", "\"=abc\"")) {
            accessTokenJson.set(bad);
            tokenClient.invalidate(record);
            tokenRequests.set(0);

            RouterException e = assertThrows(RouterException.class, () -> tokenClient.fetchAccessToken(record, "secret"), bad);
            assertEquals("Token response for payerId=PAYER-OAUTH had no usable access_token", e.getMessage());
            assertThrows(RouterException.class, () -> tokenClient.fetchAccessToken(record, "secret"), bad);
            assertEquals(2, tokenRequests.get(), "nothing may be cached for " + bad);
        }

        accessTokenJson.set(null);
        tokenRequests.set(0);
        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
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
    void cachesSeparatelyPerMtlsCredentialRef() {
        String plain = tokenClient.fetchAccessToken(record("client", List.of(), null), "secret");
        String certA = tokenClient.fetchAccessToken(record("client", List.of(), "cert-a"), "secret");
        String certB = tokenClient.fetchAccessToken(record("client", List.of(), "cert-b"), "secret");

        assertEquals(List.of("token-1", "token-2", "token-3"), List.of(plain, certA, certB));
        assertEquals(certA, tokenClient.fetchAccessToken(record("client", List.of(), "cert-a"), "secret"),
                "records with the same mtlsCredentialRef share a token");
        assertEquals(plain, tokenClient.fetchAccessToken(record("client", List.of(), null), "secret"));
        assertEquals(3, tokenRequests.get());
    }

    @Test
    void invalidateLeavesOtherMtlsCredentialRefCached() {
        ConnectionRecord plain = record("client", List.of(), null);
        ConnectionRecord withCert = record("client", List.of(), "cert-b");
        assertEquals("token-1", tokenClient.fetchAccessToken(plain, "secret"));
        assertEquals("token-2", tokenClient.fetchAccessToken(withCert, "secret"));

        tokenClient.invalidate(withCert);

        assertEquals("token-1", tokenClient.fetchAccessToken(plain, "secret"));
        assertEquals("token-3", tokenClient.fetchAccessToken(withCert, "secret"));
        assertEquals(3, tokenRequests.get());
    }

    @Test
    void concurrentColdCallersShareOneTokenRequestPerMtlsCredentialRef() throws Exception {
        tokenDelayMillis = 50;
        ConnectionRecord certA = record("client", List.of(), "cert-a");
        ConnectionRecord certB = record("client", List.of(), "cert-b");
        AtomicInteger calls = new AtomicInteger();

        List<String> tokens = concurrently(32, () ->
                tokenClient.fetchAccessToken(calls.getAndIncrement() % 2 == 0 ? certA : certB, "secret"));

        assertEquals(2, tokenRequests.get());
        assertEquals(Set.of(tokenClient.fetchAccessToken(certA, "secret"), tokenClient.fetchAccessToken(certB, "secret")),
                new HashSet<>(tokens));
        assertEquals(2, tokenRequests.get());
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
        String pem = TestKeys.privateKeyPem(TestKeys.rsa2048());
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
            awaitUntil(() -> tokenRequests.get() > 0, "first token request never reached the endpoint");
            tokenClient.invalidate(record);
            String fresh = tokenClient.fetchAccessToken(record, "secret");
            assertEquals("token-1", old.get(10, TimeUnit.SECONDS));
            assertEquals("token-2", fresh);
            assertEquals(2, tokenRequests.get());
        } finally {
            pool.shutdownNow();
        }
    }

    private static void awaitUntil(BooleanSupplier condition, String failure) throws InterruptedException {
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (!condition.getAsBoolean()) {
            if (System.nanoTime() - deadline >= 0) {
                fail(failure + " within 10 s");
            }
            Thread.sleep(5);
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

    private String origin() {
        return "http://localhost:" + server.getAddress().getPort();
    }

    private ConnectionRecord privateKeyJwtRecord(String jwksUrl) {
        return ConnectionRecord.builder().payerId("PAYER-PKJWT").environment(Environment.SANDBOX)
                .baseUrl(origin()).authType(AuthType.OAUTH2_PRIVATE_KEY_JWT).tokenEndpoint(origin() + "/token")
                .clientId("client").keyId("key-1").credentialRef("ref").jwksUrl(jwksUrl).build();
    }

    private ConnectionRecord record(List<String> scopes) {
        return record("client", scopes);
    }

    private ConnectionRecord record(String clientId, List<String> scopes) {
        return record(clientId, scopes, null);
    }

    private ConnectionRecord record(String clientId, List<String> scopes, String mtlsCredentialRef) {
        return ConnectionRecord.builder()
                .payerId("PAYER-OAUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort())
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("http://localhost:" + server.getAddress().getPort() + "/token")
                .clientId(clientId)
                .scopes(scopes)
                .credentialRef("ref")
                .mtlsCredentialRef(mtlsCredentialRef)
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
