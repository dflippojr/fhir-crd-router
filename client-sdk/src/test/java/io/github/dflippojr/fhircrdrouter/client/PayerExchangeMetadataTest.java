package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeMetadata.Outcome;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PayerExchangeMetadataTest {
    private static final String SENTINEL = "SENTINEL-SECRET-";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "pat-1"), Map.of());
    private final List<PayerExchangeMetadata> seen = new ArrayList<>();
    private HttpServer server;
    private String base;

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    private static PayerExchange exchange(OptionalInt status, Exception error) {
        return new PayerExchange(PayerCallPhase.HOOK, "payer", Environment.SANDBOX, "POST",
                URI.create("https://user:" + SENTINEL + "pw@host/" + SENTINEL + "path?q=" + SENTINEL + "q#" + SENTINEL + "f"),
                2, Instant.parse("2026-01-01T00:00:00Z"), Duration.ofMillis(7), status,
                HttpHeaders.of(Map.of("Cookie", List.of(SENTINEL + "cookie"), "X-Token", List.of(SENTINEL + "hdr")), (k, v) -> true),
                HttpHeaders.of(Map.of("X-Secret", List.of(SENTINEL + "resp")), (k, v) -> true),
                "{\"patient\":\"" + SENTINEL + "member\",\"fhirAuthorization\":{\"access_token\":\"" + SENTINEL + "tok\"},"
                        + "\"key\":\"-----BEGIN PRIVATE KEY----- " + SENTINEL + "key\",\"amount\":\"" + SENTINEL + "123\"}",
                "{\"ssn\":\"" + SENTINEL + "ssn\"}", error);
    }

    @Test
    void projectionPreservesFieldsAndLeaksNothing() throws Exception {
        Exception error = new IOException(SENTINEL + "msg", new IllegalStateException(SENTINEL + "cause"));
        PayerExchangeMetadata m = PayerExchangeMetadata.from(exchange(OptionalInt.empty(), error));
        assertEquals(PayerCallPhase.HOOK, m.phase());
        assertEquals("payer", m.payerId());
        assertEquals(Environment.SANDBOX, m.environment());
        assertEquals("POST", m.method());
        assertEquals(2, m.attempt());
        assertEquals(Instant.parse("2026-01-01T00:00:00Z"), m.startedAt());
        assertEquals(Duration.ofMillis(7), m.elapsed());
        assertTrue(m.statusCode().isEmpty());
        assertEquals(Outcome.TRANSPORT_ERROR, m.outcome());
        assertFalse(m.toString().contains(SENTINEL), m.toString());
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("phase", m.phase());
        fields.put("payerId", m.payerId());
        fields.put("environment", m.environment());
        fields.put("method", m.method());
        fields.put("attempt", m.attempt());
        fields.put("startedAt", m.startedAt().toString());
        fields.put("elapsedMs", m.elapsed().toMillis());
        fields.put("status", m.statusCode().isPresent() ? m.statusCode().getAsInt() : null);
        fields.put("outcome", m.outcome());
        assertFalse(new ObjectMapper().writeValueAsString(fields).contains(SENTINEL));
    }

    @Test
    void schemaIsExactlyTheAllowlistWithNoRetainedObjects() {
        var components = PayerExchangeMetadata.class.getRecordComponents();
        assertEquals(List.of("phase", "payerId", "environment", "method", "attempt", "startedAt", "elapsed",
                "statusCode", "outcome"), Arrays.stream(components).map(c -> c.getName()).toList());
        List<Class<?>> allowed = List.of(PayerCallPhase.class, String.class, Environment.class, int.class,
                Instant.class, Duration.class, OptionalInt.class, Outcome.class);
        for (var c : components) {
            assertTrue(allowed.contains(c.getType()), c.getType().getName());
        }
        assertEquals(List.of("HTTP_SUCCESS", "HTTP_ERROR", "TIMEOUT", "INTERRUPTED", "TRANSPORT_ERROR"),
                Arrays.stream(Outcome.values()).map(Enum::name).toList());
    }

    @Test
    void outcomesAreClassified() {
        assertEquals(Outcome.HTTP_SUCCESS, outcome(OptionalInt.of(204), null));
        assertEquals(Outcome.HTTP_ERROR, outcome(OptionalInt.of(199), null));
        assertEquals(Outcome.HTTP_ERROR, outcome(OptionalInt.of(300), null));
        assertEquals(Outcome.HTTP_ERROR, outcome(OptionalInt.of(503), null));
        assertEquals(Outcome.HTTP_ERROR, outcome(OptionalInt.of(500), new HttpTimeoutException("x")));
        assertEquals(Outcome.TIMEOUT, outcome(OptionalInt.empty(), new HttpTimeoutException("x")));
        assertEquals(Outcome.TIMEOUT, outcome(OptionalInt.empty(), new HttpConnectTimeoutException("x")));
        assertEquals(Outcome.INTERRUPTED, outcome(OptionalInt.empty(), new InterruptedException("x")));
        assertEquals(Outcome.TRANSPORT_ERROR, outcome(OptionalInt.empty(), new IOException("x")));
        assertEquals(Outcome.TRANSPORT_ERROR, outcome(OptionalInt.empty(), null));
    }

    private static Outcome outcome(OptionalInt status, Exception error) {
        return PayerExchangeMetadata.from(exchange(status, error)).outcome();
    }

    @Test
    void nullArgumentsAreRejected() {
        assertThrows(NullPointerException.class, () -> PayerExchangeMetadata.from(null));
        assertThrows(NullPointerException.class, () -> PayerExchangeListener.metadataOnly(null));
        Instant now = Instant.now();
        assertThrows(NullPointerException.class, () -> new PayerExchangeMetadata(null, "p", Environment.SANDBOX,
                "GET", 1, now, Duration.ZERO, OptionalInt.empty(), Outcome.HTTP_SUCCESS));
        assertThrows(NullPointerException.class, () -> new PayerExchangeMetadata(PayerCallPhase.HOOK, "p",
                Environment.SANDBOX, "GET", 1, now, Duration.ZERO, null, Outcome.HTTP_SUCCESS));
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void everyAuthTypeReportsMetadata(AuthType auth) throws Exception {
        start();
        server.createContext("/token", e -> respond(e, 200, "{\"access_token\":\"" + SENTINEL + "t\",\"expires_in\":300}"));
        server.createContext("/cds-services/x", e -> respond(e, 200, "{\"cards\":[]}"));
        String secret = auth == AuthType.CDS_HOOKS_JWT || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT
                ? TestKeys.privateKeyPem(TestKeys.ec("secp384r1")) : "client-secret-unique";
        client(secret, PayerExchangeListener.metadataOnly(seen::add), Duration.ofSeconds(2)).callHook(record(auth), "x", REQUEST);
        boolean oauth = auth == AuthType.OAUTH2_CLIENT_CREDENTIALS || auth == AuthType.OAUTH2_PRIVATE_KEY_JWT;
        assertEquals(oauth ? 2 : 1, seen.size());
        assertEquals(PayerCallPhase.HOOK, seen.get(seen.size() - 1).phase());
        seen.forEach(m -> {
            assertEquals(Outcome.HTTP_SUCCESS, m.outcome());
            assertFalse(m.toString().contains(SENTINEL));
        });
    }

    @Test
    void oauth401OrderAndCacheHitsArePreserved() throws Exception {
        start();
        AtomicInteger tokens = new AtomicInteger();
        AtomicInteger hooks = new AtomicInteger();
        server.createContext("/token", e -> respond(e, 200, "{\"access_token\":\"t" + tokens.incrementAndGet() + "\",\"expires_in\":300}"));
        server.createContext("/cds-services/x", e -> respond(e, hooks.incrementAndGet() == 1 ? 401 : 200, "{\"cards\":[]}"));
        CdsHooksClient client = client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofSeconds(2));
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS);
        client.callHook(record, "x", REQUEST);
        assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.HOOK, PayerCallPhase.TOKEN, PayerCallPhase.HOOK),
                seen.stream().map(PayerExchangeMetadata::phase).toList());
        assertEquals(List.of(1, 1, 2, 2), seen.stream().map(PayerExchangeMetadata::attempt).toList());
        assertEquals(List.of(Outcome.HTTP_SUCCESS, Outcome.HTTP_ERROR, Outcome.HTTP_SUCCESS, Outcome.HTTP_SUCCESS),
                seen.stream().map(PayerExchangeMetadata::outcome).toList());
        client.callHook(record, "x", REQUEST);
        assertEquals(5, seen.size());
        assertEquals(2, tokens.get());
    }

    @Test
    void retryAttemptsReport429And503InOrder() throws Exception {
        start();
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/cds-services", e -> {
            e.getResponseHeaders().add("Retry-After", "0");
            int n = calls.incrementAndGet();
            respond(e, n == 1 ? 429 : n == 2 ? 503 : 200, "{\"services\":[]}");
        });
        client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofSeconds(2))
                .retryPolicy(new RetryPolicy(3, Duration.ofSeconds(1)))
                .discoverServices(record(AuthType.NONE));
        assertEquals(List.of(1, 2, 3), seen.stream().map(PayerExchangeMetadata::attempt).toList());
        assertEquals(List.of(429, 503, 200), seen.stream().map(m -> m.statusCode().orElseThrow()).toList());
        assertEquals(List.of(Outcome.HTTP_ERROR, Outcome.HTTP_ERROR, Outcome.HTTP_SUCCESS),
                seen.stream().map(PayerExchangeMetadata::outcome).toList());
    }

    @Test
    void malformedHttp200IsSuccessEvenWhenParsingFails() throws Exception {
        start();
        server.createContext("/cds-services/x", e -> respond(e, 200, "not json " + SENTINEL));
        CdsHooksClient client = client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofSeconds(2));
        assertThrows(RouterException.class, () -> client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertEquals(1, seen.size());
        assertEquals(Outcome.HTTP_SUCCESS, seen.get(0).outcome());
    }

    @Test
    void timeoutAndTransportFailureProduceFixedOutcomes() throws Exception {
        start();
        server.createContext("/cds-services/x", e -> {
            try {
                Thread.sleep(250);
                respond(e, 200, "{\"cards\":[]}");
            } catch (Exception ignored) {
                Thread.currentThread().interrupt();
            }
        });
        CdsHooksClient slow = client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofMillis(50));
        ConnectionRecord record = record(AuthType.NONE);
        assertThrows(PayerCallException.class, () -> slow.callHook(record, "x", REQUEST));
        assertEquals(Outcome.TIMEOUT, seen.get(0).outcome());
        server.stop(0);
        seen.clear();
        assertThrows(PayerCallException.class, () -> slow.callHook(record, "x", REQUEST));
        assertEquals(Outcome.TRANSPORT_ERROR, seen.get(0).outcome());
        assertTrue(seen.get(0).statusCode().isEmpty());
    }

    @Test
    void throwingConsumerDoesNotChangeResult() throws Exception {
        start();
        server.createContext("/cds-services/x", e -> respond(e, 200, "{\"cards\":[]}"));
        CdsHooksClient client = client(PayerExchangeListener.metadataOnly(m -> {
            seen.add(m);
            throw new IllegalStateException("consumer failure");
        }), Duration.ofSeconds(2));
        assertNotNull(client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertEquals(1, seen.size());
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

    private CdsHooksClient client(PayerExchangeListener listener, Duration timeout) {
        return client("client-secret-unique", listener, timeout);
    }

    private CdsHooksClient client(String secret, PayerExchangeListener listener, Duration timeout) {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.of(secret); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, timeout, Duration.ofSeconds(1), listener);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (var out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }
}
