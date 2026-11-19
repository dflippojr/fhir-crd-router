package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

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
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private LoopbackPayer payer;
    private CdsHooksClient client;

    @BeforeEach
    void start() {
        payer = new LoopbackPayer();
        payer.otherwise(request -> NOT_FOUND);
        payer.on("/token", request -> {
            tokenRequests.incrementAndGet();
            if (GOOD_BASIC.equals(request.authorization())) {
                return plain(200, "{\"access_token\":\"good-token\",\"expires_in\":300}");
            }
            return plain(401, "{\"error\":\"invalid_client\"}");
        });
        payer.on("/cds-services", request -> plain(200,
                request.rawPath().equals("/cds-services") ? CATALOG : "{\"cards\":[]}"));
        client = new CdsHooksClient(HttpClient.newHttpClient(), provider(), null,
                CdsHooksClient.DEFAULT_REQUEST_TIMEOUT, CdsHooksClient.DEFAULT_CONNECT_TIMEOUT, exchanges::add);
    }

    @AfterEach
    void stop() {
        payer.close();
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
        payer.on("/cds-services", request -> plain(
                request.rawPath().equals("/cds-services") ? 401 : 200, "{\"cards\":[]}"));

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
        payer.on("/cds-services", plain(401, "{}"));

        assertEquals(OptionalInt.of(401), client.verify(record()).failureStatus());

        assertEquals(1, tokenRequests.get());
    }

    @Test
    void throttleRetriesReuseTheVerifysOneToken() {
        AtomicInteger discoveries = new AtomicInteger();
        payer.on("/cds-services", request -> discoveries.incrementAndGet() == 1
                ? plain(429, "{}").withHeader("Retry-After", "0")
                : plain(200, CATALOG));
        client.retryPolicy(new RetryPolicy(3, Duration.ofSeconds(1)));

        assertTrue(client.verify(record()).ok());

        assertEquals(2, discoveries.get());
        assertEquals(1, tokenRequests.get());
    }

    private ConnectionRecord record() {
        return TestRecords.oauth2(payer).payerId("PAYER-ROTATED").clientId("synthetic-client").build();
    }

    /** {@code body} with no Content-Type, as the hand-rolled server sent it. */
    private static Reply plain(int status, String body) {
        return new Reply(status, body, Map.of());
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
