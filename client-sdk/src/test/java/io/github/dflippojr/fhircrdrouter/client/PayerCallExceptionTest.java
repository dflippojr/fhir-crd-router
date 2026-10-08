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

import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import io.github.dflippojr.fhircrdrouter.client.auth.OAuth2TokenClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PayerCallExceptionTest {
    private static final String SECRET = "synthetic-secret";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of(), Map.of());
    private static final CredentialProvider CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String ref) { return Optional.of(SECRET); }
        @Override public void put(String ref, String value) { }
        @Override public void remove(String ref) { }
    };
    private HttpServer server;
    private String base;
    private final CountDownLatch release = new CountDownLatch(1);

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
    }

    @Test
    void hook401RetainsStatusAndOnlyAllowedHeadersAfterOneOAuthRetry() {
        AtomicInteger tokens = new AtomicInteger();
        AtomicInteger hooks = new AtomicInteger();
        respond("/token", 200, "{\"access_token\":\"granted\"}", Map.of(), tokens);
        respond("/cds-services/hook", 401, "denied", Map.of(
                "WWW-Authenticate", "Bearer error=\"invalid_token\"",
                "X-Request-Id", "request-1", "X-Correlation-Id", "correlation-1",
                "Set-Cookie", "secret-cookie", "Content-Type", "application/json"), hooks);
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> client().callHookRaw(record(true), "hook", REQUEST));
        assertInstanceOf(RouterException.class, error);
        assertEquals(PayerCallPhase.HOOK, error.phase());
        assertEquals("PAYER-TEST", error.payerId());
        assertEquals(URI.create(base + "/cds-services/hook"), error.uri());
        assertEquals(OptionalInt.of(401), error.statusCode());
        assertEquals("Bearer error=\"invalid_token\"", error.responseHeaders().firstValue("www-AUTHENTICATE").orElseThrow());
        assertEquals("request-1", error.responseHeaders().firstValue("x-request-id").orElseThrow());
        assertEquals("correlation-1", error.responseHeaders().firstValue("X-Correlation-Id").orElseThrow());
        assertEquals("application/json", error.responseHeaders().firstValue("Content-Type").orElseThrow());
        assertTrue(error.responseHeaders().firstValue("Set-Cookie").isEmpty());
        assertEquals("denied", error.responseBody());
        assertEquals("Hook call for payerId=PAYER-TEST serviceId=hook failed: payer returned HTTP 401: denied", error.getMessage());
        assertFalse(error.timedOut());
        assertEquals(2, tokens.get());
        assertEquals(2, hooks.get());
    }

    @Test
    void discovery429ExposesRetryAfterAndBoundsUtf8Body() {
        respond("/cds-services", 429, "\u20ac".repeat(2000), Map.of("Retry-After", "30"), new AtomicInteger());
        PayerCallException error = assertThrows(PayerCallException.class, () -> client().discoverServices(record(false)));
        assertEquals(PayerCallPhase.DISCOVERY, error.phase());
        assertEquals(OptionalInt.of(429), error.statusCode());
        assertEquals("30", error.responseHeaders().firstValue("retry-after").orElseThrow());
        assertEquals(4095, error.responseBody().getBytes(StandardCharsets.UTF_8).length);
        assertEquals("\u20ac".repeat(1365), error.responseBody());
        assertThrows(UnsupportedOperationException.class,
                () -> error.responseHeaders().map().put("Retry-After", List.of("10")));
    }

    @Test
    void token400KeepsOnlyRfcFieldsAndRedactsEchoedSecret() {
        respond("/token", 400, "{\"error\":\"invalid_client\",\"error_description\":\"bad " + SECRET
                + "\",\"access_token\":\"token-secret\",\"extra\":\"hidden\"}", Map.of(), new AtomicInteger());
        PayerCallException error = assertThrows(PayerCallException.class, () -> client().discoverServices(record(true)));
        assertEquals(PayerCallPhase.TOKEN, error.phase());
        assertEquals(URI.create(base + "/token"), error.uri());
        assertEquals(OptionalInt.of(400), error.statusCode());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"bad [REDACTED]\"}", error.responseBody());
        for (String sensitive : List.of(SECRET, "token-secret", "hidden", "access_token", "extra")) {
            assertFalse(error.toString().contains(sensitive));
            assertFalse(error.responseBody().contains(sensitive));
        }
    }

    @Test
    void malformedTokenErrorOmitsRawBody() {
        respond("/token", 500, SECRET, Map.of(), new AtomicInteger());
        PayerCallException error = assertThrows(PayerCallException.class, () -> client().discoverServices(record(true)));
        assertEquals("{}", error.responseBody());
        assertFalse(error.toString().contains(SECRET));
    }

    @Test
    void malformedSuccessfulTokenBodyNeverAppearsInExceptionOrCause() {
        respond("/token", 200, "{\"access_token\":\"" + SECRET, Map.of(), new AtomicInteger());
        RouterException error = assertThrows(RouterException.class, () -> client().discoverServices(record(true)));
        assertFalse(error.toString().contains(SECRET));
        assertNull(error.getCause());
    }

    @Test
    void discoveryTimeoutHasNoStatus() { assertTimeoutPhase(false, false, PayerCallPhase.DISCOVERY); }

    @Test
    void hookTimeoutHasNoStatus() { assertTimeoutPhase(false, true, PayerCallPhase.HOOK); }

    @Test
    void tokenTimeoutHasNoStatus() { assertTimeoutPhase(true, false, PayerCallPhase.TOKEN); }

    private void assertTimeoutPhase(boolean oauth, boolean hook, PayerCallPhase phase) {
        server.createContext(oauth ? "/token" : "/cds-services", exchange -> {
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } finally {
                exchange.close();
            }
        });
        PayerCallException error = assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertThrows(PayerCallException.class, () -> {
                    if (hook) { client().callHookRaw(record(oauth), "hook", REQUEST); }
                    else { client().discoverServices(record(oauth)); }
                }));
        assertEquals(phase, error.phase());
        assertTrue(error.timedOut());
        assertTrue(error.statusCode().isEmpty());
        assertTrue(error.responseHeaders().map().isEmpty());
        assertEquals("", error.responseBody());
    }

    @Test
    void refusedConnectionHasTransportDiagnostics() throws Exception {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) { port = socket.getLocalPort(); }
        base = "http://127.0.0.1:" + port;
        PayerCallException error = assertThrows(PayerCallException.class, () -> client().discoverServices(record(false)));
        assertEquals(PayerCallPhase.DISCOVERY, error.phase());
        assertTrue(error.statusCode().isEmpty());
        assertFalse(error.timedOut());
        assertNotNull(error.getCause());
    }

    @Test
    void validatesTimeoutsAndTruncatesAsciiBodies() {
        assertThrows(IllegalArgumentException.class,
                () -> new CdsHooksClient(CREDENTIALS, Duration.ZERO, Duration.ofSeconds(1)));
        assertThrows(IllegalArgumentException.class,
                () -> new CdsHooksClient(CREDENTIALS, Duration.ofSeconds(1), Duration.ofSeconds(-1)));
        var error = new PayerCallException("prefix: ", PayerCallPhase.HOOK, "payer", URI.create(base),
                null, "a".repeat(5000));
        assertEquals(4096, error.responseBody().length());
    }

    @Test
    void interruptedCallsPreserveInterruptFlagAndPhase() {
        for (boolean oauth : List.of(false, true)) {
            Thread.currentThread().interrupt();
            try {
                PayerCallException error = assertThrows(PayerCallException.class,
                        () -> client().discoverServices(record(oauth)));
                assertEquals(oauth ? PayerCallPhase.TOKEN : PayerCallPhase.DISCOVERY, error.phase());
                assertTrue(Thread.currentThread().isInterrupted());
                assertFalse(error.timedOut());
            } finally {
                Thread.interrupted();
            }
        }
    }

    @Test
    void tokenConnectionRefusedIsTypedAndStandaloneTimeoutMustBePositive() throws Exception {
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2TokenClient(HttpClient.newHttpClient(), Duration.ZERO));
        assertThrows(IllegalArgumentException.class,
                () -> new OAuth2TokenClient(HttpClient.newHttpClient(), Duration.ofSeconds(-1)));
        int port;
        try (ServerSocket socket = new ServerSocket(0)) { port = socket.getLocalPort(); }
        base = "http://127.0.0.1:" + port;
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> client().discoverServices(record(true)));
        assertEquals(PayerCallPhase.TOKEN, error.phase());
        assertTrue(error.statusCode().isEmpty());
        assertFalse(error.timedOut());
    }

    private CdsHooksClient client() {
        return new CdsHooksClient(HttpClient.newHttpClient(), CREDENTIALS, null,
                Duration.ofMillis(300), Duration.ofSeconds(1));
    }

    private ConnectionRecord record(boolean oauth) {
        var builder = ConnectionRecord.builder().payerId("PAYER-TEST").environment(Environment.SANDBOX).baseUrl(base);
        if (oauth) {
            builder.authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).tokenEndpoint(base + "/token")
                    .clientId("synthetic-client").credentialRef("secret-ref");
        } else { builder.authType(AuthType.NONE); }
        return builder.build();
    }

    private void respond(String path, int status, String body, Map<String, String> headers, AtomicInteger calls) {
        server.createContext(path, exchange -> {
            calls.incrementAndGet();
            headers.forEach((k, v) -> exchange.getResponseHeaders().add(k, v));
            TestResponses.respond(exchange, status, body);
        });
    }
}
