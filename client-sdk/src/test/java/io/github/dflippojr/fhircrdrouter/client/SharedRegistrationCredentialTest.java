package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Records that share a token endpoint, client ID and scopes but not a credential (#192): a warm token
 * from one must not vouch for another's wrong, unset or unresolvable {@code credentialRef}.
 */
class SharedRegistrationCredentialTest {

    private static final CdsHookRequest REQUEST =
            new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of());
    private static final String GOOD_BASIC = "Basic " + Base64.getEncoder().encodeToString(
            "synthetic-client:good-secret".getBytes(StandardCharsets.UTF_8));

    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger goodResolves = new AtomicInteger();
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
        server.createContext("/cds-services", exchange -> {
            boolean authorized = "Bearer good-token".equals(exchange.getRequestHeaders().getFirst("Authorization"));
            String body = exchange.getRequestURI().getPath().equals("/cds-services")
                    ? "{\"services\":[{\"id\":\"order-sign-crd\",\"hook\":\"order-sign\",\"description\":\"Synthetic\"}]}"
                    : "{\"cards\":[]}";
            TestResponses.respond(exchange, authorized ? 200 : 401, body);
        });
        server.start();
        client = new CdsHooksClient(HttpClient.newHttpClient(), provider());
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void verifyReportsAWrongSecretWhateverAnotherRecordCached() {
        assertTrue(client.verify(record("good")).ok());

        ConnectionVerification report = client.verify(record("bad"));

        assertFalse(report.ok());
        assertEquals(Optional.of(PayerCallPhase.TOKEN), report.failurePhase());
        assertEquals(OptionalInt.of(401), report.failureStatus());
        assertEquals("token request returned HTTP 401", report.failureReason());
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void verifyReportsAnUnsetCredentialRefWhateverAnotherRecordCached() {
        assertMissingCredential(null);
    }

    @Test
    void verifyReportsAnUnresolvableCredentialRefWhateverAnotherRecordCached() {
        assertMissingCredential("does-not-exist");
    }

    private void assertMissingCredential(String credentialRef) {
        assertTrue(client.verify(record("good")).ok());

        ConnectionVerification report = client.verify(record(credentialRef));

        assertFalse(report.ok());
        assertEquals(Optional.of(PayerCallPhase.TOKEN), report.failurePhase());
        assertEquals(OptionalInt.empty(), report.failureStatus());
        assertEquals("missing credential for token request", report.failureReason());
        assertEquals(1, tokenRequests.get(), "nothing to send without a credential");
    }

    @Test
    void payerCallsDoNotUseAnotherRecordsToken() {
        client.callHook(record("good"), "order-sign-crd", REQUEST);

        PayerCallException wrong = assertThrows(PayerCallException.class,
                () -> client.callHook(record("bad"), "order-sign-crd", REQUEST));
        assertEquals(PayerCallPhase.TOKEN, wrong.phase());
        assertEquals(OptionalInt.of(401), wrong.statusCode());
        assertEquals("authType=OAUTH2_CLIENT_CREDENTIALS but no credentialRef set for payerId=PAYER-SHARED",
                assertThrows(RouterException.class,
                        () -> client.callHook(record(null), "order-sign-crd", REQUEST)).getMessage());
    }

    @Test
    void aFailedRecordLeavesTheWorkingRecordsTokenCached() {
        client.callHook(record("good"), "order-sign-crd", REQUEST);
        assertFalse(client.verify(record("bad")).ok());
        assertEquals(1, goodResolves.get());

        client.callHook(record("good"), "order-sign-crd", REQUEST);

        assertEquals(1, goodResolves.get(), "a warm call must not read the secret (#52)");
        assertEquals(2, tokenRequests.get());
    }

    private ConnectionRecord record(String credentialRef) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return ConnectionRecord.builder()
                .payerId("PAYER-SHARED").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint(base + "/token")
                .clientId("synthetic-client").credentialRef(credentialRef).build();
    }

    private CredentialProvider provider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) {
                return switch (ref) {
                    case "good" -> {
                        goodResolves.incrementAndGet();
                        yield Optional.of("good-secret");
                    }
                    case "bad" -> Optional.of("wrong-secret");
                    default -> Optional.empty();
                };
            }
            @Override public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            @Override public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
    }
}
