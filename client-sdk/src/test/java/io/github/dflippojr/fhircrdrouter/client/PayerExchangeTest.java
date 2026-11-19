package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeMetadata.Outcome;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PayerExchangeTest {
    private static final String RESPONSE = "{\"cards\":[]}";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "pat-1"), Map.of());
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private LoopbackPayer payer;
    private String base;
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));
    private final CountDownLatch release = new CountDownLatch(1);

    @AfterEach
    void stop() {
        release.countDown();
        if (payer != null) {
            try {
                // A test that closed the payer itself to cause a transport failure has nothing to probe.
                if (!payer.isClosed()) {
                    UnroutedGuard.assertUnroutedIsNotFound(payer);
                }
            } finally {
                payer.close();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void everyAuthTypeRedactsSecretsAndPreservesHookBodies(AuthType auth) throws Exception {
        start();
        String secret = auth == AuthType.CDS_HOOKS_JWT || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT
                ? TestKeys.privateKeyPem(TestKeys.ec("secp384r1")) : "client-secret-unique";
        List<String> sensitive = new ArrayList<>(List.of(secret, "access-token-unique", "cookie-secret"));
        payer.on("/token", request -> {
            rememberCredentials(request, sensitive);
            return respond(200, "{\"access_token\":\"access-token-unique\",\"refresh_token\":\"refresh-secret\","
                    + "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"crd\"}");
        });
        payer.on("/cds-services/x", request -> {
            rememberCredentials(request, sensitive);
            return respond(200, RESPONSE);
        });
        CdsHooksClient client = client(secret, exchanges::add, Duration.ofSeconds(2));
        client.callHook(record(auth), "x", REQUEST);
        boolean oauth = auth == AuthType.OAUTH2_CLIENT_CREDENTIALS || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT;
        assertEquals(oauth ? 2 : 1, exchanges.size());
        for (PayerExchange exchange : exchanges) {
            // The record's generated toString includes every field, including headers and error.
            for (String value : sensitive) {
                assertFalse(exchange.toString().contains(value), exchange.toString());
            }
            assertFalse(exchange.toString().contains("refresh-secret"));
            assertEquals("payer", exchange.payerId());
            assertEquals(Environment.SANDBOX, exchange.environment());
            assertEquals(1, exchange.attempt());
            assertEquals(200, exchange.statusCode().orElseThrow());
            PayerExchangeMetadata metadata = PayerExchangeMetadata.from(exchange);
            assertEquals(Outcome.HTTP_SUCCESS, metadata.outcome());
            for (String value : sensitive) {
                assertFalse(metadata.toString().contains(value), metadata.toString());
            }
            assertNull(exchange.error());
            assertFalse(exchange.elapsed().isNegative());
            assertFalse(exchange.startedAt().isAfter(Instant.now()));
            assertTrue(exchange.responseHeaders().allValues("Set-Cookie").isEmpty());
            assertEquals("trace-1", exchange.responseHeaders().firstValue("X-Request-Id").orElseThrow());
            exchange.requestHeaders().firstValue("Authorization").ifPresent(v ->
                    assertTrue(v.equals("Bearer [REDACTED]") || v.equals("Basic [REDACTED]")));
            assertThrows(UnsupportedOperationException.class, () -> exchange.responseHeaders().map().clear());
            assertThrows(UnsupportedOperationException.class, () -> exchange.responseHeaders().allValues("X-Request-Id").clear());
        }
        if (oauth) {
            PayerExchange token = exchanges.get(0);
            assertEquals(PayerCallPhase.TOKEN, token.phase());
            assertNull(token.requestBody());
            assertEquals(new ObjectMapper().readTree("{\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"crd\"}"),
                    new ObjectMapper().readTree(token.responseBody()));
        }
        PayerExchange hook = exchanges.get(exchanges.size() - 1);
        assertEquals(PayerCallPhase.HOOK, hook.phase());
        assertEquals("POST", hook.method());
        assertEquals(base + "/cds-services/x", hook.uri().toString());
        assertEquals(new ObjectMapper().writeValueAsString(REQUEST), hook.requestBody());
        assertEquals(RESPONSE, hook.responseBody());
    }

    @Test
    void oauth401ReportsTokenAndHookAttemptsInOrderAndCacheHitsAreNotExchanges() throws Exception {
        start();
        AtomicInteger tokens = new AtomicInteger();
        AtomicInteger hooks = new AtomicInteger();
        payer.on("/token", request -> respond(200,
                "{\"access_token\":\"token-" + tokens.incrementAndGet() + "\",\"expires_in\":300}"));
        payer.on("/cds-services/x", request -> respond(hooks.incrementAndGet() == 1 ? 401 : 200, RESPONSE));
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofSeconds(2));
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS);
        client.callHook(record, "x", REQUEST);
        assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.HOOK, PayerCallPhase.TOKEN, PayerCallPhase.HOOK),
                exchanges.stream().map(PayerExchange::phase).toList());
        assertEquals(List.of(1, 1, 2, 2), exchanges.stream().map(PayerExchange::attempt).toList());
        assertEquals(List.of(200, 401, 200, 200), exchanges.stream().map(e -> e.statusCode().orElseThrow()).toList());
        assertEquals(List.of(Outcome.HTTP_SUCCESS, Outcome.HTTP_ERROR, Outcome.HTTP_SUCCESS, Outcome.HTTP_SUCCESS),
                exchanges.stream().map(e -> PayerExchangeMetadata.from(e).outcome()).toList());
        client.callHook(record, "x", REQUEST);
        assertEquals(5, exchanges.size());
        assertEquals(2, tokens.get());
    }

    @Test
    void discoveryIsReportedAndThrowingListenerDoesNotChangeResult() throws Exception {
        start();
        payer.on("/cds-services", respond(200, "{\"services\":[]}"));
        CdsHooksClient client = client("secret", e -> {
            exchanges.add(e);
            throw new IllegalStateException("listener failure");
        }, Duration.ofSeconds(2));
        assertTrue(client.discoverServices(record(AuthType.NONE)).isEmpty());
        assertEquals(PayerCallPhase.DISCOVERY, exchanges.get(0).phase());
        assertEquals("GET", exchanges.get(0).method());
        assertNull(exchanges.get(0).requestBody());
    }

    @ParameterizedTest
    @EnumSource(value = AuthType.class, names = {"NONE", "OAUTH2_CLIENT_CREDENTIALS"})
    void transportFailureIsReportedWithOriginalErrorAndNoStatus(AuthType auth) throws Exception {
        start();
        payer.close();
        CdsHooksClient client = client("secret", e -> {
            exchanges.add(e);
            throw new IllegalStateException("listener failure");
        }, Duration.ofSeconds(1));
        PayerCallException error = assertThrows(PayerCallException.class, () -> client.callHook(record(auth), "x", REQUEST));
        assertEquals(1, exchanges.size());
        PayerExchange exchange = exchanges.get(0);
        assertEquals(auth == AuthType.NONE ? PayerCallPhase.HOOK : PayerCallPhase.TOKEN, exchange.phase());
        assertSame(error.getCause(), exchange.error());
        assertTrue(exchange.statusCode().isEmpty());
        assertTrue(exchange.responseHeaders().map().isEmpty());
        assertNull(exchange.responseBody());
    }

    @Test
    void timeoutIsReported() throws Exception {
        start();
        payer.on("/cds-services/x", request -> {
            try {
                release.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            // The client timed out long before this reply, so it never reads it.
            return respond(200, RESPONSE);
        });
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofMillis(50));
        PayerCallException error = assertThrows(PayerCallException.class, () -> client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertTrue(error.timedOut());
        assertSame(error.getCause(), exchanges.get(0).error());
        assertTrue(exchanges.get(0).statusCode().isEmpty());
    }

    @ParameterizedTest
    @ValueSource(strings = {"not-json access-token-unique", "null", "{\"access_token\":\"access-token-unique\"}",
            "{\"scope\":{\"access_token\":\"access-token-unique\"},\"token_type\":[]}"})
    void failedTokenResponsesNeverExposeRawBody(String body) throws Exception {
        start();
        payer.on("/token", respond(400, body));
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofSeconds(2));
        assertThrows(PayerCallException.class, () -> client.callHook(record(AuthType.OAUTH2_CLIENT_CREDENTIALS), "x", REQUEST));
        assertEquals(1, exchanges.size());
        assertEquals("{}", exchanges.get(0).responseBody());
        assertEquals(400, exchanges.get(0).statusCode().orElseThrow());
        assertNull(exchanges.get(0).error());
    }

    @Test
    void nonObjectHookBodyIsReportedAsOneExchange() throws Exception {
        start();
        payer.on("/cds-services/x", respond(200, "[]"));
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofSeconds(2));
        assertThrows(RouterException.class, () -> client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertEquals(1, exchanges.size());
        assertEquals(PayerCallPhase.HOOK, exchanges.get(0).phase());
        assertEquals(200, exchanges.get(0).statusCode().orElseThrow());
        assertEquals("[]", exchanges.get(0).responseBody());
        assertNull(exchanges.get(0).error());
    }

    private void start() {
        payer = new LoopbackPayer();
        payer.otherwise(request -> NOT_FOUND);
        base = payer.origin();
    }

    private ConnectionRecord record(AuthType auth) {
        return TestRecords.forAuth(auth, base).payerId("payer").credentialRef(TestRecords.CREDENTIAL_REF)
                .clientId(TestRecords.CLIENT_ID).keyId("key").tokenEndpoint(base + TestRecords.TOKEN_PATH).build();
    }

    private CdsHooksClient client(String secret, PayerExchangeListener listener, Duration timeout) {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.of(secret); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, timeout, Duration.ofSeconds(1), listener);
    }

    private static void rememberCredentials(Received request, List<String> sensitive) {
        String header = request.authorization();
        if (header != null) {
            sensitive.add(header.substring(header.indexOf(' ') + 1));
        }
        String body = URLDecoder.decode(request.body(), StandardCharsets.UTF_8);
        for (String pair : body.split("&")) {
            if (pair.startsWith("client_assertion=")) {
                sensitive.add(pair.substring("client_assertion=".length()));
            }
        }
    }

    /** {@code body} with a cookie and a request ID, and no {@code Content-Type}, as the hand-rolled server sent it. */
    private static Reply respond(int status, String body) {
        return new Reply(status, body, Map.of()).withHeader("sEt-CoOkIe", "session=cookie-secret")
                .withHeader("X-Request-Id", "trace-1");
    }
}
