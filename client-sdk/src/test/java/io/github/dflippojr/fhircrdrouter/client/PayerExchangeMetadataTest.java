package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeMetadata.Outcome;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.UnroutedGuard;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpConnectTimeoutException;
import java.net.http.HttpHeaders;
import java.net.http.HttpTimeoutException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class PayerExchangeMetadataTest {
    private static final String SENTINEL = "SENTINEL-SECRET-";
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "pat-1"), Map.of());
    private final List<PayerExchangeMetadata> seen = new ArrayList<>();
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

    @Test
    void retryAttemptsReport429And503InOrder() throws Exception {
        start();
        AtomicInteger calls = new AtomicInteger();
        payer.on("/cds-services", request -> {
            int n = calls.incrementAndGet();
            return respond(n == 1 ? 429 : n == 2 ? 503 : 200, "{\"services\":[]}").withHeader("Retry-After", "0");
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
        payer.on("/cds-services/x", respond(200, "not json " + SENTINEL));
        CdsHooksClient client = client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofSeconds(2));
        assertThrows(RouterException.class, () -> client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertEquals(1, seen.size());
        assertEquals(Outcome.HTTP_SUCCESS, seen.get(0).outcome());
    }

    @Test
    void timeoutAndTransportFailureProduceFixedOutcomes() throws Exception {
        start();
        payer.on("/cds-services/x", request -> {
            try {
                release.await();
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            }
            // The client timed out long before this reply, so it never reads it.
            return respond(200, "{\"cards\":[]}");
        });
        CdsHooksClient slow = client(PayerExchangeListener.metadataOnly(seen::add), Duration.ofMillis(50));
        ConnectionRecord record = record(AuthType.NONE);
        assertThrows(PayerCallException.class, () -> slow.callHook(record, "x", REQUEST));
        assertEquals(Outcome.TIMEOUT, seen.get(0).outcome());
        release.countDown();
        payer.close();
        seen.clear();
        assertThrows(PayerCallException.class, () -> slow.callHook(record, "x", REQUEST));
        assertEquals(Outcome.TRANSPORT_ERROR, seen.get(0).outcome());
        assertTrue(seen.get(0).statusCode().isEmpty());
    }

    @Test
    void throwingConsumerDoesNotChangeResult() throws Exception {
        start();
        payer.on("/cds-services/x", respond(200, "{\"cards\":[]}"));
        CdsHooksClient client = client(PayerExchangeListener.metadataOnly(m -> {
            seen.add(m);
            throw new IllegalStateException("consumer failure");
        }), Duration.ofSeconds(2));
        assertNotNull(client.callHook(record(AuthType.NONE), "x", REQUEST));
        assertEquals(1, seen.size());
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

    /** {@code body} with no {@code Content-Type}, as the hand-rolled server sent it. */
    private static Reply respond(int status, String body) {
        return new Reply(status, body, Map.of());
    }
}
