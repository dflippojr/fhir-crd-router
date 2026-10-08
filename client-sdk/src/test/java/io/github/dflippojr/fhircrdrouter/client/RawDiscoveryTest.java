package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class RawDiscoveryTest {
    private HttpServer server;
    private ConnectionRecord record;
    private final AtomicInteger calls = new AtomicInteger();
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private String body = "{\"services\":[]}";
    private int status = 200;
    private boolean rejectFirst;
    private boolean blockResponse;
    private final CountDownLatch releaseResponse = new CountDownLatch(1);

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/cds-services", e -> {
            int count = calls.incrementAndGet();
            if (blockResponse) {
                try {
                    releaseResponse.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    e.close();
                    return;
                }
            }
            e.getResponseHeaders().add("Retry-After", "0");
            respond(e, rejectFirst && count == 1 ? status : (rejectFirst ? 200 : status), body);
        });
        server.start();
        record = connection(AuthType.NONE);
    }

    @AfterEach
    void stop() {
        releaseResponse.countDown();
        server.stop(0);
    }

    @Test
    void rawPreservesNumericFieldsAndTypedDiscoveryRemainsLenient() {
        body = "{\"services\":[{\"id\":42,\"hook\":7,\"description\":12}],\"extra\":true}";
        JsonNode raw = client().discoverServicesRaw(record);
        assertTrue(raw.get("services").get(0).get("id").isInt());
        assertTrue(raw.get("extra").booleanValue());
        assertEquals(3, CdsDiscoveryValidator.validate(raw).size());
        assertEquals(1, calls.get());
        var typed = client().discoverServices(record);
        assertEquals("42", typed.get(0).id());
        assertEquals("7", typed.get(0).hook());
        assertEquals("12", typed.get(0).description());
        assertEquals(2, calls.get());
        body = "{\"services\":[{}]}";
        assertNull(client().discoverServices(record).get(0).id());
    }

    @Test
    void distinguishesMalformedCatalogsFromValidEmptyCatalog() {
        for (String json : List.of("{}", "{\"services\":{}}", "{\"services\":[]}")) {
            body = json;
            JsonNode raw = client().discoverServicesRaw(record);
            assertEquals(json.endsWith("[]}") ? 0 : 1, CdsDiscoveryValidator.validate(raw).size());
            assertTrue(client().discoverServices(record).isEmpty());
        }
        assertEquals(6, calls.get());
        assertEquals(6, exchanges.size());
    }

    @Test
    void rawPreservesMalformedRootShapesForOfflineDiagnosis() {
        for (String json : List.of("null", "[]", "42", "true", "\"text\"")) {
            body = json;
            JsonNode raw = client().discoverServicesRaw(record);
            assertEquals(json, raw.toString());
            assertEquals("$", CdsDiscoveryValidator.validate(raw).get(0).path());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sharesApiKeyAuthAndRedactedListener(boolean raw) {
        record = connection(AuthType.API_KEY);
        discover(client(), raw);
        assertEquals(1, calls.get());
        assertEquals(List.of("Bearer synthetic-secret"), serverAuth);
        assertEquals(1, exchanges.size());
        var exchange = exchanges.get(0);
        assertEquals(PayerCallPhase.DISCOVERY, exchange.phase());
        assertEquals("GET", exchange.method());
        assertEquals("Bearer [REDACTED]", exchange.requestHeaders().firstValue("Authorization").orElseThrow());
        assertEquals(body, exchange.responseBody());
        assertFalse(exchange.toString().contains("synthetic-secret"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sharesConfiguredThrottleRetry(boolean raw) {
        status = 503;
        rejectFirst = true;
        discover(client().retryPolicy(new RetryPolicy(2, Duration.ofSeconds(1))), raw);
        assertEquals(2, calls.get());
        assertEquals(List.of(1, 2), exchanges.stream().map(PayerExchange::attempt).toList());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sharesOAuthRefreshRetry(boolean raw) {
        status = 401;
        rejectFirst = true;
        AtomicInteger tokens = new AtomicInteger();
        server.createContext("/token", e -> respond(e, 200,
                "{\"access_token\":\"synthetic-token-" + tokens.incrementAndGet() + "\",\"expires_in\":300}"));
        record = connection(AuthType.OAUTH2_CLIENT_CREDENTIALS);
        discover(client(), raw);
        assertEquals(2, calls.get());
        assertEquals(2, tokens.get());
        assertEquals(List.of(PayerCallPhase.TOKEN, PayerCallPhase.DISCOVERY,
                PayerCallPhase.TOKEN, PayerCallPhase.DISCOVERY),
                exchanges.stream().map(PayerExchange::phase).toList());
        assertEquals("Bearer synthetic-token-1", serverAuth.get(0));
        assertEquals("Bearer synthetic-token-2", serverAuth.get(1));
    }

    private final List<String> serverAuth = new ArrayList<>();

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sharesTypedHttpErrorsAndParseErrorWording(boolean raw) {
        status = 403;
        PayerCallException failure = assertThrows(PayerCallException.class, () -> discover(client(), raw));
        assertEquals(PayerCallPhase.DISCOVERY, failure.phase());
        assertEquals(403, failure.statusCode().orElseThrow());
        status = 200;
        body = "not-json";
        RouterException parseError = assertThrows(RouterException.class, () -> discover(client(), raw));
        assertEquals("Discovery call for payerId=PAYER-SYNTHETIC returned an unparseable body", parseError.getMessage());
        body = "{\"services\":[{\"id\":{}}]}";
        if (raw) {
            assertEquals(3, CdsDiscoveryValidator.validate(client().discoverServicesRaw(record)).size());
        } else {
            assertEquals(parseError.getMessage(), assertThrows(RouterException.class,
                    () -> client().discoverServices(record)).getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void sharesRequestTimeoutAndTransportListener(boolean raw) {
        blockResponse = true;
        CdsHooksClient client = new CdsHooksClient(null, Duration.ofMillis(200),
                Duration.ofSeconds(2), exchanges::add);
        PayerCallException failure = assertThrows(PayerCallException.class, () -> discover(client, raw));
        assertTrue(failure.timedOut());
        assertEquals(PayerCallPhase.DISCOVERY, failure.phase());
        assertTrue(failure.statusCode().isEmpty());
        assertEquals(1, exchanges.size());
        assertNotNull(exchanges.get(0).error());
        assertEquals(1, exchanges.get(0).attempt());
    }

    private void discover(CdsHooksClient client, boolean raw) {
        if (raw) {
            client.discoverServicesRaw(record);
        } else {
            client.discoverServices(record);
        }
    }

    private ConnectionRecord connection(AuthType auth) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return ConnectionRecord.builder().payerId("PAYER-SYNTHETIC").environment(Environment.SANDBOX)
                .baseUrl(base + "/").authType(auth).credentialRef("synthetic")
                .clientId("synthetic-client").tokenEndpoint(base + "/token").build();
    }

    private CdsHooksClient client() {
        CredentialProvider credentials = new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.of("synthetic-secret"); }
            @Override public void put(String ref, String value) { }
            @Override public void remove(String ref) { }
        };
        return new CdsHooksClient(credentials, Duration.ofSeconds(2), Duration.ofSeconds(2), exchanges::add);
    }

    private void respond(HttpExchange exchange, int code, String json) throws IOException {
        if (exchange.getRequestURI().getPath().equals("/cds-services")) {
            serverAuth.add(exchange.getRequestHeaders().getFirst("Authorization"));
        }
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        try (var stream = exchange.getResponseBody()) {
            stream.write(bytes);
        }
    }
}
