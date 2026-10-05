package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PayerExchangeTest {
    private static final String RESPONSE = "{\"cards\":[]}";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "pat-1"), Map.of());
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private HttpServer server;
    private String base;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void everyAuthTypeRedactsSecretsAndPreservesHookBodies(AuthType auth) throws Exception {
        start();
        String secret = auth == AuthType.CDS_HOOKS_JWT || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT
                ? TestKeys.privateKeyPem(TestKeys.ec("secp384r1")) : "client-secret-unique";
        List<String> sensitive = new ArrayList<>(List.of(secret, "access-token-unique", "cookie-secret"));
        server.createContext("/token", e -> {
            rememberCredentials(e, sensitive);
            respond(e, 200, "{\"access_token\":\"access-token-unique\",\"refresh_token\":\"refresh-secret\","
                    + "\"token_type\":\"Bearer\",\"expires_in\":300,\"scope\":\"crd\"}");
        });
        server.createContext("/cds-services/x", e -> {
            rememberCredentials(e, sensitive);
            respond(e, 200, RESPONSE);
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
        server.createContext("/token", e -> respond(e, 200,
                "{\"access_token\":\"token-" + tokens.incrementAndGet() + "\",\"expires_in\":300}"));
        server.createContext("/cds-services/x", e -> respond(e, hooks.incrementAndGet() == 1 ? 401 : 200, RESPONSE));
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofSeconds(2));
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS);
        client.callHook(record, "x", REQUEST);
        assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.HOOK, PayerCallPhase.TOKEN, PayerCallPhase.HOOK),
                exchanges.stream().map(PayerExchange::phase).toList());
        assertEquals(List.of(1, 1, 2, 2), exchanges.stream().map(PayerExchange::attempt).toList());
        assertEquals(List.of(200, 401, 200, 200), exchanges.stream().map(e -> e.statusCode().orElseThrow()).toList());
        client.callHook(record, "x", REQUEST);
        assertEquals(5, exchanges.size());
        assertEquals(2, tokens.get());
    }

    @Test
    void discoveryIsReportedAndThrowingListenerDoesNotChangeResult() throws Exception {
        start();
        server.createContext("/cds-services", e -> respond(e, 200, "{\"services\":[]}"));
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
        server.stop(0);
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
        server.createContext("/cds-services/x", e -> {
            try {
                Thread.sleep(250);
                respond(e, 200, RESPONSE);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
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
        server.createContext("/token", e -> respond(e, 400, body));
        CdsHooksClient client = client("secret", exchanges::add, Duration.ofSeconds(2));
        assertThrows(PayerCallException.class, () -> client.callHook(record(AuthType.OAUTH2_CLIENT_CREDENTIALS), "x", REQUEST));
        assertEquals(1, exchanges.size());
        assertEquals("{}", exchanges.get(0).responseBody());
        assertEquals(400, exchanges.get(0).statusCode().orElseThrow());
        assertNull(exchanges.get(0).error());
    }

    private void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
    }

    private ConnectionRecord record(AuthType auth) {
        return ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(auth).credentialRef("credential").clientId("client")
                .keyId("key").tokenEndpoint(base + "/token").build();
    }

    private CdsHooksClient client(String secret, PayerExchangeListener listener, Duration timeout) {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.of(secret); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, timeout, Duration.ofSeconds(1), listener);
    }

    private static void rememberCredentials(HttpExchange exchange, List<String> sensitive) throws IOException {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        if (header != null) {
            sensitive.add(header.substring(header.indexOf(' ') + 1));
        }
        String body = URLDecoder.decode(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8), StandardCharsets.UTF_8);
        for (String pair : body.split("&")) {
            if (pair.startsWith("client_assertion=")) {
                sensitive.add(pair.substring("client_assertion=".length()));
            }
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().add("sEt-CoOkIe", "session=cookie-secret");
        exchange.getResponseHeaders().add("X-Request-Id", "trace-1");
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
