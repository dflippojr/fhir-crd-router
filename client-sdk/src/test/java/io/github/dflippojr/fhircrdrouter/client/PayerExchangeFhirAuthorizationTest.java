package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHookRequest.FhirAuthorization;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

/**
 * The EHR's FHIR {@code access_token} sent in a hook request's {@code fhirAuthorization}
 * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
 * Passing the Access Token to the CDS Service</a>) never reaches a listener: not in the request body,
 * not echoed in the response body, and not in {@link PayerExchange#toString()} (#164).
 */
class PayerExchangeFhirAuthorizationTest {
    private static final String TOKEN = "SENTINEL-EHR-ACCESS-TOKEN-164";
    private static final String EHR = "https://ehr.example.org/fhir";
    private static final FhirAuthorization AUTH =
            new FhirAuthorization(TOKEN, "Bearer", 300, "patient/Patient.read", "payer-client", "pat-1");
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance",
            Map.of("patientId", "pat-1"), Map.of()).withFhirServer(EHR, AUTH);
    private final ObjectMapper mapper = new ObjectMapper();
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private final LoopbackPayer payer = new LoopbackPayer();

    private final List<HttpServer> servers = new ArrayList<>();

    @AfterEach
    void stop() {
        payer.close();
        servers.forEach(server -> server.stop(0));
    }

    @Test
    void hookRequestBodyRedactsOnlyTheAccessToken() throws Exception {
        payer.reset(r -> new LoopbackPayer.Reply(200, "{\"cards\":[]}"));

        client().callHook(record(), "x", REQUEST);

        // The payer still gets the token: redaction is for listeners only.
        assertEquals(TOKEN, mapper.readTree(payer.received().get(0).body())
                .at("/fhirAuthorization/access_token").asText());
        PayerExchange hook = single();
        assertNoToken(hook);
        JsonNode sent = mapper.readTree(hook.requestBody());
        assertEquals("[REDACTED]", sent.at("/fhirAuthorization/access_token").asText());
        // Everything else in the body is what was sent, so a listener can still debug the call.
        JsonNode expected = mapper.valueToTree(REQUEST);
        ((com.fasterxml.jackson.databind.node.ObjectNode) expected.get("fhirAuthorization"))
                .put("access_token", "[REDACTED]");
        assertEquals(expected, sent);
    }

    @Test
    void tokenEchoedInHookResponseBodyIsRedacted() throws Exception {
        payer.reset(r -> new LoopbackPayer.Reply(200,
                "{\"cards\":[{\"summary\":\"saw " + TOKEN + "\",\"indicator\":\"info\",\"source\":{\"label\":\"p\"}}]}"));

        client().callHook(record(), "x", REQUEST);

        PayerExchange hook = single();
        assertNoToken(hook);
        assertTrue(hook.responseBody().contains("saw [REDACTED]"), hook.responseBody());
    }

    @Test
    void tokenEchoedInHookErrorBodyIsRedacted() {
        payer.reset(r -> new LoopbackPayer.Reply(400, "{\"error\":\"bad token " + TOKEN + "\"}"));

        assertThrows(PayerCallException.class, () -> client().callHook(record(), "x", REQUEST));

        PayerExchange hook = single();
        assertNoToken(hook);
        assertTrue(hook.responseBody().contains("bad token [REDACTED]"), hook.responseBody());
    }

    @Test
    void tokenInResponseHeadersIsRedactedOnSuccess() throws Exception {
        HttpServer server = headerServer(List.of(200));

        client().callHook(record(server), "x", REQUEST);

        assertHeadersClean(single());
    }

    @Test
    void tokenInResponseHeadersIsRedactedOnErrorAndRetry() throws Exception {
        HttpServer server = headerServer(List.of(429, 400));

        assertThrows(PayerCallException.class, () -> client().retryPolicy(new RetryPolicy(2, Duration.ofSeconds(2)))
                .callHook(record(server), "x", REQUEST));

        assertEquals(List.of(OptionalInt.of(429), OptionalInt.of(400)),
                exchanges.stream().map(PayerExchange::statusCode).toList());
        exchanges.forEach(PayerExchangeFhirAuthorizationTest::assertHeadersClean);
    }

    @Test
    void tokenInAnyJsonStringSpellingIsRedacted() throws Exception {
        String token = "tok/164/secret/x";
        CdsHookRequest request = REQUEST.withFhirServer(EHR,
                new FhirAuthorization(token, "Bearer", 300, "patient/Patient.read", "payer-client"));
        // Each spelling decodes to the token; only one slash of the first is escaped.
        payer.reset(r -> new LoopbackPayer.Reply(200, "{\"cards\":[],\"extension\":{\"detail\":{\"nested\":["
                + "\"a tok\\/164/secret/x b\",\"tok/164\\/secret\\/x\",\"\\u0074ok/164/secret/x\"]}}}"));

        client().callHook(record(), "x", request);

        PayerExchange hook = single();
        assertFalse(hook.toString().contains(token), hook.toString());
        assertFalse(hook.toString().contains("164\\/secret"), hook.toString());
        assertFalse(hook.toString().contains("tok\\/164"), hook.toString());
        List<String> strings = new ArrayList<>();
        collectStrings(mapper.readTree(hook.responseBody()), strings);
        assertFalse(strings.isEmpty());
        for (String value : strings) {
            assertFalse(value.contains(token), value);
        }
        assertFalse(collectStringsOf(mapper.readTree(hook.requestBody())).stream().anyMatch(v -> v.contains(token)));
    }

    @Test
    void payerCallExceptionCarriesNoTokenInMessageBodyOrHeaders() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/cds-services/x", e -> {
            e.getRequestBody().readAllBytes();
            e.getResponseHeaders().add("X-Request-Id", "id " + TOKEN);
            e.getResponseHeaders().add("Retry-After", "7");
            TestResponses.respond(e, 503, "{\"error\":\"bad " + TOKEN.replace("-", "\\u002d") + "\"}");
        });
        server.start();
        servers.add(server);

        PayerCallException e = assertThrows(PayerCallException.class,
                () -> client().callHook(record(server), "x", REQUEST));

        assertFalse(e.getMessage().contains(TOKEN), e.getMessage());
        assertFalse(collectStringsOf(mapper.readTree(e.responseBody())).stream().anyMatch(v -> v.contains(TOKEN)),
                e.responseBody());
        assertEquals(List.of("id [REDACTED]"), e.responseHeaders().allValues("X-Request-Id"));
        assertEquals(Optional.of(Duration.ofSeconds(7)), e.retryAfter());
        assertEquals(503, e.statusCode().orElseThrow());
    }

    @Test
    void retryTimingStillComesFromThePayerWhenTheRequestCannotBeRead() throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/cds-services/x", e -> {
            e.getRequestBody().readAllBytes();
            boolean first = calls.getAndIncrement() == 0;
            if (first) {
                e.getResponseHeaders().add("Retry-After", "0");
            }
            TestResponses.respond(e, first ? 429 : 200, "{\"cards\":[]}");
        });
        server.start();
        servers.add(server);
        // A prefetch string past Jackson's read limit: valid to send, but the SDK cannot read it back.
        CdsHookRequest large = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "pat-1"),
                Map.of("big", "x".repeat(com.fasterxml.jackson.core.StreamReadConstraints.DEFAULT_MAX_STRING_LEN + 1)))
                .withFhirServer(EHR, AUTH);

        client().retryPolicy(new RetryPolicy(2, Duration.ofSeconds(2))).callHook(record(server), "x", large);

        assertEquals(2, calls.get());
    }

    /** A token Jackson quotes whole in a parse error: letters and digits only. */
    private static final String PLAIN = "SentinelEhrToken164plain";
    private static final CdsHookRequest PLAIN_REQUEST = new CdsHookRequest("order-sign", "instance",
            Map.of("patientId", "pat-1"), Map.of()).withFhirServer(EHR,
            new FhirAuthorization(PLAIN, "Bearer", 300, "patient/Patient.read", "payer-client"));

    @Test
    void unparseableHookResponseExceptionCarriesNoToken() {
        payer.reset(r -> new LoopbackPayer.Reply(200, "{\"cards\":" + PLAIN + "}"));

        RouterException e = assertThrows(RouterException.class, () -> client().callHookRaw(record(), "x", PLAIN_REQUEST));

        assertNoTokenInChain(e, PLAIN);
        assertNull(e.getCause(), "no cause leaves a token-bearing call");
        assertTrue(e.getMessage().contains("com.fasterxml.jackson.core.JsonParseException: "), e.getMessage());
    }

    @Test
    void unmappableHookResponseExceptionCarriesNoToken() {
        payer.reset(r -> new LoopbackPayer.Reply(200, "{\"cards\":[{\"suggestions\":[\"" + PLAIN + "\"]}]}"));

        RouterException e = assertThrows(RouterException.class, () -> client().callHook(record(), "x", PLAIN_REQUEST));

        assertNoTokenInChain(e, PLAIN);
        assertNull(e.getCause());
        assertTrue(e.getMessage().contains("(cause: "), e.getMessage());
    }

    @Test
    void hookTransportFailureExceptionCarriesNoToken() throws Exception {
        try (java.net.ServerSocket socket = new java.net.ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress())) {
            Thread server = new Thread(() -> {
                try (java.net.Socket client = socket.accept()) {
                    client.getInputStream().read(new byte[8192]);
                    client.getOutputStream().write(("HTTP/1.1 2x0 " + PLAIN + "\r\n\r\n")
                            .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                    client.getOutputStream().flush();
                } catch (java.io.IOException ignored) {
                    // The client may close first.
                }
            });
            server.start();
            ConnectionRecord record = ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                    .baseUrl("http://127.0.0.1:" + socket.getLocalPort()).authType(AuthType.NONE).build();

            PayerCallException e = assertThrows(PayerCallException.class,
                    () -> client().callHook(record, "x", PLAIN_REQUEST));
            server.join(5000);

            assertNoTokenInChain(e, PLAIN);
            assertNull(e.getCause());
            assertTrue(e.getMessage().contains("java.net.ProtocolException: "), e.getMessage());
            assertFalse(e.timedOut());
        }
        exchanges.forEach(exchange -> assertFalse(exchange.toString().contains(PLAIN), exchange.toString()));
    }

    private static void assertNoTokenInChain(Throwable error, String token) {
        java.io.StringWriter printed = new java.io.StringWriter();
        error.printStackTrace(new java.io.PrintWriter(printed));
        assertFalse(printed.toString().contains(token), printed.toString());
        for (Throwable t = error; t != null; t = t.getCause()) {
            assertFalse(String.valueOf(t).contains(token), String.valueOf(t));
            for (Throwable s : t.getSuppressed()) {
                assertFalse(String.valueOf(s).contains(token), String.valueOf(s));
            }
        }
    }

    private static void collectStrings(JsonNode node, List<String> out) {
        if (node.isTextual()) {
            out.add(node.asText());
        }
        node.fieldNames().forEachRemaining(out::add);
        node.elements().forEachRemaining(child -> collectStrings(child, out));
    }

    private static List<String> collectStringsOf(JsonNode node) {
        List<String> out = new ArrayList<>();
        collectStrings(node, out);
        return out;
    }

    /** Answers each call with the next status, echoing the token in response header values. */
    private HttpServer headerServer(List<Integer> statuses) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger calls = new AtomicInteger();
        server.createContext("/cds-services/x", e -> {
            e.getRequestBody().readAllBytes();
            int status = statuses.get(Math.min(calls.getAndIncrement(), statuses.size() - 1));
            e.getResponseHeaders().add("X-Request-Id", TOKEN);
            e.getResponseHeaders().add("X-Echo", "seen " + TOKEN + " here");
            if (status == 429) {
                e.getResponseHeaders().add("Retry-After", "0");
            }
            TestResponses.respond(e, status, "{\"cards\":[]}");
        });
        server.start();
        servers.add(server);
        return server;
    }

    private static void assertHeadersClean(PayerExchange exchange) {
        assertNoToken(exchange);
        assertEquals(List.of("[REDACTED]"), exchange.responseHeaders().allValues("X-Request-Id"));
        assertEquals(List.of("seen [REDACTED] here"), exchange.responseHeaders().allValues("X-Echo"));
    }

    private ConnectionRecord record(HttpServer server) {
        return ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl("http://127.0.0.1:" + server.getAddress().getPort()).authType(AuthType.NONE).build();
    }

    private PayerExchange single() {
        assertEquals(1, exchanges.size());
        PayerExchange hook = exchanges.get(0);
        assertEquals(PayerCallPhase.HOOK, hook.phase());
        return hook;
    }

    private static void assertNoToken(PayerExchange exchange) {
        assertFalse(exchange.toString().contains(TOKEN), exchange.toString());
        exchange.responseHeaders().map().forEach((name, values) -> {
            assertFalse(name.contains(TOKEN), name);
            values.forEach(value -> assertFalse(value.contains(TOKEN), value));
        });
        assertFalse(exchange.requestBody().contains(TOKEN), exchange.requestBody());
        assertFalse(exchange.responseBody().contains(TOKEN), exchange.responseBody());
        assertFalse(PayerExchangeMetadata.from(exchange).toString().contains(TOKEN));
    }

    private ConnectionRecord record() {
        return ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(payer.origin()).authType(AuthType.NONE).build();
    }

    private CdsHooksClient client() {
        CredentialProvider credentials = new CredentialProvider() {
            public Optional<String> resolve(String ref) { return Optional.empty(); }
            public void put(String ref, String value) { throw new UnsupportedOperationException(); }
            public void remove(String ref) { throw new UnsupportedOperationException(); }
        };
        return new CdsHooksClient(HttpClient.newHttpClient(), credentials, null, Duration.ofSeconds(5),
                Duration.ofSeconds(1), exchanges::add);
    }
}
