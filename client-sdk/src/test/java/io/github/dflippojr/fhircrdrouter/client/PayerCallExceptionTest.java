package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
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
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.*;

class PayerCallExceptionTest {
    private static final String SECRET = "synthetic-secret";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of(), Map.of());
    private static final CredentialProvider CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String ref) { return Optional.of(SECRET); }
        @Override public void put(String ref, String value) { }
        @Override public void remove(String ref) { }
    };
    private static final String API_KEY = "synthetic-api-key-123";
    private static final String SIGNING_KEY = TestKeys.privateKeyPem(TestKeys.ec("secp384r1"));
    /** Resolves "api-key" to {@link #API_KEY}, "signing-key" to a PEM private key and anything else to {@link #SECRET}. */
    private static final CredentialProvider KEYED_CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String ref) {
            return Optional.of(switch (ref) {
                case "api-key" -> API_KEY;
                case "signing-key" -> SIGNING_KEY;
                default -> SECRET;
            });
        }
        @Override public void put(String ref, String value) { }
        @Override public void remove(String ref) { }
    };
    private LoopbackPayer payer;
    private String base;
    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));
    private final CountDownLatch release = new CountDownLatch(1);

    @BeforeEach
    void start() {
        payer = new LoopbackPayer();
        payer.otherwise(request -> NOT_FOUND);
        base = payer.origin();
    }

    @AfterEach
    void stop() {
        release.countDown();
        try {
            UnroutedGuard.assertUnroutedIsNotFound(payer);
        } finally {
            payer.close();
        }
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
        payer.on(oauth ? "/token" : "/cds-services", request -> {
            try {
                release.await();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            // The client timed out long before this reply, so it never reads it.
            return plain(200, "{}");
        });
        CdsHooksClient client = shortTimeoutClient();
        PayerCallException error = assertTimeoutPreemptively(Duration.ofSeconds(2),
                () -> assertThrows(PayerCallException.class, () -> {
                    if (hook) { client.callHookRaw(record(oauth), "hook", REQUEST); }
                    else { client.discoverServices(record(oauth)); }
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

    @Test
    void discovery401RedactsEchoedApiKey() {
        payer.on("/cds-services", request -> plain(401,
                "{\"error\":\"bad key in header: " + request.authorization() + "\"}"));
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> keyedClient().discoverServices(keyedRecord(AuthType.API_KEY)));
        assertEquals(PayerCallPhase.DISCOVERY, error.phase());
        assertEquals("{\"error\":\"bad key in header: Bearer [REDACTED]\"}", error.responseBody());
        assertRedacted(error, API_KEY);
    }

    @Test
    void hook401RedactsEchoedAccessToken() {
        List<String> issued = new CopyOnWriteArrayList<>();
        payer.on("/token", request -> {
            String token = "synthetic-access-token-" + issued.size();
            issued.add(token);
            return plain(200, "{\"access_token\":\"" + token + "\"}");
        });
        payer.on("/cds-services/hook", request -> plain(401,
                "rejected " + bearer(request.authorization())));
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> keyedClient().callHookRaw(keyedRecord(AuthType.OAUTH2_CLIENT_CREDENTIALS), "hook", REQUEST));
        assertEquals(PayerCallPhase.HOOK, error.phase());
        assertEquals(2, issued.size());
        assertEquals("rejected [REDACTED]", error.responseBody());
        issued.forEach(token -> assertRedacted(error, token));
    }

    @Test
    void hook401RedactsEchoedCdsHooksJwt() {
        AtomicReference<String> received = new AtomicReference<>();
        payer.on("/cds-services/hook", request -> {
            received.set(bearer(request.authorization()));
            return plain(401, "rejected " + received.get());
        });
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> keyedClient().callHookRaw(keyedRecord(AuthType.CDS_HOOKS_JWT), "hook", REQUEST));
        assertEquals(PayerCallPhase.HOOK, error.phase());
        assertNotNull(received.get());
        assertEquals("rejected [REDACTED]", error.responseBody());
        assertRedacted(error, received.get());
    }

    @Test
    void token400RedactsEchoedClientAssertion() {
        AtomicReference<String> received = new AtomicReference<>();
        payer.on("/token", request -> {
            received.set(formField(request.body(), "client_assertion"));
            return plain(400, "{\"error\":\"invalid_client\",\"error_description\":"
                    + "\"rejected assertion " + received.get() + "\"}");
        });
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> keyedClient().discoverServices(keyedRecord(AuthType.OAUTH2_PRIVATE_KEY_JWT)));
        assertEquals(PayerCallPhase.TOKEN, error.phase());
        assertNotNull(received.get());
        assertEquals("{\"error\":\"invalid_client\",\"error_description\":\"rejected assertion [REDACTED]\"}",
                error.responseBody());
        assertRedacted(error, received.get());
    }

    @Test
    void echoedKeyAtTruncationBoundaryLeavesNoPrefix() {
        // Ten characters of the key fall before the 4096-byte limit and the rest after it.
        payer.on("/cds-services", request -> plain(401,
                "a".repeat(4096 - 10) + bearer(request.authorization()) + " tail"));
        PayerCallException error = assertThrows(PayerCallException.class,
                () -> keyedClient().discoverServices(keyedRecord(AuthType.API_KEY)));
        for (int i = 0; i + 8 <= API_KEY.length(); i++) {
            String window = API_KEY.substring(i, i + 8);
            assertFalse(error.responseBody().contains(window), window);
            assertFalse(error.getMessage().contains(window), window);
        }
    }

    private static void assertRedacted(PayerCallException error, String credential) {
        assertFalse(error.getMessage().contains(credential));
        assertFalse(error.responseBody().contains(credential));
        assertFalse(error.toString().contains(credential));
        assertTrue(error.responseBody().contains("[REDACTED]"));
    }

    private static String bearer(String authorization) {
        return authorization.substring("Bearer ".length());
    }

    private static String formField(String form, String name) {
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            if (pair.substring(0, eq).equals(name)) {
                return URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    private CdsHooksClient keyedClient() {
        return new CdsHooksClient(HttpClient.newHttpClient(), KEYED_CREDENTIALS, null,
                Duration.ofSeconds(5), Duration.ofSeconds(1));
    }

    private ConnectionRecord keyedRecord(AuthType authType) {
        var builder = TestRecords.forAuth(authType, base);
        // The credential refs pick the secret KEYED_CREDENTIALS resolves.
        switch (authType) {
            case API_KEY -> builder.credentialRef("api-key");
            case OAUTH2_CLIENT_CREDENTIALS -> builder.clientId("synthetic-client").credentialRef("secret-ref");
            case OAUTH2_PRIVATE_KEY_JWT, CDS_HOOKS_JWT -> builder.clientId("synthetic-client")
                    .credentialRef("signing-key");
            case NONE -> { }
        }
        return builder.build();
    }

    private CdsHooksClient client() {
        return new CdsHooksClient(HttpClient.newHttpClient(), CREDENTIALS, null,
                Duration.ofMillis(300), Duration.ofSeconds(1));
    }

    // The handler never answers in the timeout tests, so a short timeout cannot cause a spurious failure.
    private CdsHooksClient shortTimeoutClient() {
        return new CdsHooksClient(HttpClient.newHttpClient(), CREDENTIALS, null,
                Duration.ofMillis(50), Duration.ofSeconds(1));
    }

    private ConnectionRecord record(boolean oauth) {
        if (oauth) {
            return TestRecords.forAuth(AuthType.OAUTH2_CLIENT_CREDENTIALS, base).clientId("synthetic-client")
                    .credentialRef("secret-ref").build();
        }
        return TestRecords.forAuth(AuthType.NONE, base).build();
    }

    private void respond(String path, int status, String body, Map<String, String> headers, AtomicInteger calls) {
        payer.on(path, request -> {
            calls.incrementAndGet();
            Reply reply = plain(status, body);
            for (Map.Entry<String, String> header : headers.entrySet()) {
                reply = reply.withHeader(header.getKey(), header.getValue());
            }
            return reply;
        });
    }

    /** {@code body} with no {@code Content-Type} unless a test adds one, as the hand-rolled server sent it. */
    private static Reply plain(int status, String body) {
        return new Reply(status, body, Map.of());
    }
}
