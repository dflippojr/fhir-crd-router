package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code verify} proves the credential works before {@code lastVerifiedAt} is saved, so it always
 * exchanges a fresh token; payer calls keep using the cache (#218).
 */
class VerifyFreshTokenTest {

    private static final CdsHookRequest REQUEST =
            new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of());
    private static final String CATALOG =
            "{\"services\":[{\"id\":\"order-sign-crd\",\"hook\":\"order-sign\",\"description\":\"Synthetic\"}]}";
    private static final String GOOD_BASIC = "Basic " + Base64.getEncoder().encodeToString(
            "synthetic-client:good-secret".getBytes(StandardCharsets.UTF_8));

    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final List<PayerExchange> exchanges = new CopyOnWriteArrayList<>();
    private volatile String secret = "good-secret";
    private HttpServer server;
    private CdsHooksClient client;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/token", exchange -> {
            tokenRequests.incrementAndGet();
            if (GOOD_BASIC.equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                TestResponses.respond(exchange, 200, "{\"access_token\":\"good-token\",\"expires_in\":300}");
            } else {
                TestResponses.respond(exchange, 401, "{\"error\":\"invalid_client\"}");
            }
        });
        server.createContext("/cds-services", exchange -> TestResponses.respond(exchange, 200,
                exchange.getRequestURI().getPath().equals("/cds-services") ? CATALOG : "{\"cards\":[]}"));
        server.start();
        client = new CdsHooksClient(HttpClient.newHttpClient(), provider(), null,
                CdsHooksClient.DEFAULT_REQUEST_TIMEOUT, CdsHooksClient.DEFAULT_CONNECT_TIMEOUT, exchanges::add);
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void aSecretRotatedToAWrongValueFailsTheNextVerifyDespiteAWarmCache() {
        // verify never fills the cache, so a payer call warms it.
        client.callHook(record(), "order-sign-crd", REQUEST);
        assertTrue(client.verify(record()).ok());
        secret = "wrong-secret";

        ConnectionVerification report = client.verify(record());

        assertFalse(report.ok(), "a warm cache must not vouch for the rotated secret");
        assertEquals(Optional.of(PayerCallPhase.TOKEN), report.failurePhase());
        assertEquals(OptionalInt.of(401), report.failureStatus());
        assertEquals("token request returned HTTP 401", report.failureReason());
    }

    @Test
    void eachVerifyMakesExactlyOneTokenRequestWhateverTheCacheHolds() {
        client.callHook(record(), "order-sign-crd", REQUEST);
        assertEquals(1, tokenRequests.get());

        for (int verifies = 1; verifies <= 3; verifies++) {
            assertTrue(client.verify(record()).ok());
            assertEquals(1 + verifies, tokenRequests.get());
        }

        assertEquals(3, exchanges.stream().filter(e -> e.phase() == PayerCallPhase.DISCOVERY).count());
        assertEquals(4, exchanges.stream().filter(e -> e.phase() == PayerCallPhase.TOKEN).count());
    }

    @Test
    void payerCallsStillMakeNoTokenRequestWhenAValidTokenIsCached() {
        client.callHook(record(), "order-sign-crd", REQUEST);
        client.verify(record());
        int afterVerify = tokenRequests.get();

        client.callHook(record(), "order-sign-crd", REQUEST);
        client.discoverServices(record());

        assertEquals(afterVerify, tokenRequests.get());
    }

    @Test
    void aFailedVerifyLeavesTheCachedTokenUsable() {
        client.callHook(record(), "order-sign-crd", REQUEST);
        secret = "wrong-secret";
        assertFalse(client.verify(record()).ok());
        int afterVerify = tokenRequests.get();

        client.callHook(record(), "order-sign-crd", REQUEST);

        assertEquals(afterVerify, tokenRequests.get(), "the failed verify dropped the cached token");
    }

    /** A 401 on a just-issued token is the answer: a second exchange would break "exactly one" and prove nothing. */
    @Test
    void aDiscovery401IsReportedAfterOneTokenRequestAndLeavesTheCacheAlone() {
        client.callHook(record(), "order-sign-crd", REQUEST);
        int before = tokenRequests.get();
        server.removeContext("/cds-services");
        server.createContext("/cds-services", exchange -> TestResponses.respond(exchange,
                exchange.getRequestURI().getPath().equals("/cds-services") ? 401 : 200, "{\"cards\":[]}"));

        ConnectionVerification report = client.verify(record());

        assertFalse(report.ok());
        assertEquals(Optional.of(PayerCallPhase.DISCOVERY), report.failurePhase());
        assertEquals(OptionalInt.of(401), report.failureStatus());
        assertEquals(before + 1, tokenRequests.get());

        client.callHook(record(), "order-sign-crd", REQUEST);
        assertEquals(before + 1, tokenRequests.get(), "the failed verify dropped the cached token");
    }

    @Test
    void aDiscovery401OnAColdCacheDoesNotExchangeASecondToken() {
        server.removeContext("/cds-services");
        server.createContext("/cds-services", exchange -> TestResponses.respond(exchange, 401, "{}"));

        assertEquals(OptionalInt.of(401), client.verify(record()).failureStatus());

        assertEquals(1, tokenRequests.get());
    }

    @Test
    void throttleRetriesReuseTheVerifysOneToken() {
        AtomicInteger discoveries = new AtomicInteger();
        server.removeContext("/cds-services");
        server.createContext("/cds-services", exchange -> {
            if (discoveries.incrementAndGet() == 1) {
                exchange.getResponseHeaders().add("Retry-After", "0");
                TestResponses.respond(exchange, 429, "{}");
            } else {
                TestResponses.respond(exchange, 200, CATALOG);
            }
        });
        client.retryPolicy(new RetryPolicy(3, Duration.ofSeconds(1)));

        assertTrue(client.verify(record()).ok());

        assertEquals(2, discoveries.get());
        assertEquals(1, tokenRequests.get());
    }

    private ConnectionRecord record() {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return ConnectionRecord.builder()
                .payerId("PAYER-ROTATED").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint(base + "/token")
                .clientId("synthetic-client").credentialRef("rotating").build();
    }

    private CredentialProvider provider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) {
                return Optional.of(secret);
            }
            @Override public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            @Override public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
    }
}
