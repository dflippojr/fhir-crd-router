package io.github.dflippojr.fhircrdrouter.client.internal;

import com.fasterxml.jackson.core.StreamReadConstraints;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchange;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/** What {@link ExchangeSender} hands a listener: the redaction arms the client-level tests never reach (#201). */
class ExchangeSenderTest {
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private HttpServer server;
    private String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.start();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @Test
    void authorizationWithoutSchemeIsFullyRedacted() throws Exception {
        server.createContext("/cds-services/x", e -> TestResponses.respond(e, 200, "{\"cards\":[]}"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services/x"))
                .header("Authorization", "opaque-secret-201")
                .timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofString("{}")).build();

        send(request, "{}", PayerCallPhase.HOOK);

        PayerExchange exchange = exchanges.get(0);
        assertEquals(List.of("[REDACTED]"), exchange.requestHeaders().allValues("Authorization"));
        assertFalse(exchange.toString().contains("opaque-secret-201"), exchange.toString());
    }

    @Test
    void tokenBodyDropsNonScalarAllowedFields() throws Exception {
        server.createContext("/token", e -> TestResponses.respond(e, 200,
                "{\"access_token\":\"access-token-201\",\"token_type\":[\"x\"],"
                        + "\"scope\":{\"nested\":\"synthetic-leak\"},\"expires_in\":3600}"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/token")).timeout(Duration.ofSeconds(5))
                .POST(HttpRequest.BodyPublishers.ofString("grant_type=client_credentials")).build();

        send(request, "grant_type=client_credentials", PayerCallPhase.TOKEN);

        PayerExchange exchange = exchanges.get(0);
        assertEquals("{\"expires_in\":3600}", exchange.responseBody());
        for (String leak : List.of("access-token-201", "access_token", "synthetic-leak", "token_type", "scope")) {
            assertFalse(exchange.toString().contains(leak), leak + " in " + exchange);
        }
    }

    @Test
    void hookBodyWithoutAccessTokenPassesThroughUnchanged() {
        for (String body : List.of("{\"hook\":\"x\",\"n\":1.10}", "[]", "null", "{\"fhirAuthorization\":\"s\"}",
                "{\"fhirAuthorization\":{\"scope\":\"s\"}}")) {
            assertEquals(new ExchangeSender.HookBody(body, null), ExchangeSender.redactFhirAuthorization(body));
        }
        assertEquals(new ExchangeSender.HookBody(null, null), ExchangeSender.redactFhirAuthorization(null));
    }

    @Test
    void unparseableHookBodyIsOmitted() {
        assertEquals(ExchangeSender.HookBody.UNREADABLE,
                ExchangeSender.redactFhirAuthorization("{\"fhirAuthorization\":{\"access_token\":\"tok-164\""));
        assertEquals(new ExchangeSender.HookBody("", null), ExchangeSender.redactFhirAuthorization(""));
    }

    @Test
    void unreadableHookRequestOmitsTheResponseToo() throws Exception {
        // A string past Jackson's read limit is valid JSON the SDK can send but cannot inspect (#229 review).
        String token = "tok-164-unreadable";
        String sent = "{\"fhirAuthorization\":{\"access_token\":\"" + token + "\"},\"prefetch\":{\"big\":\""
                + "x".repeat(StreamReadConstraints.DEFAULT_MAX_STRING_LEN + 1) + "\"}}";
        server.createContext("/cds-services/x", e -> {
            e.getRequestBody().transferTo(java.io.OutputStream.nullOutputStream());
            TestResponses.respond(e, 400, "{\"error\":\"" + token + "\"}");
        });
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services/x"))
                .timeout(Duration.ofSeconds(30)).POST(HttpRequest.BodyPublishers.ofString(sent)).build();

        send(request, sent, PayerCallPhase.HOOK);

        PayerExchange exchange = exchanges.get(0);
        assertEquals(400, exchange.statusCode().orElseThrow());
        assertNull(exchange.requestBody());
        assertNull(exchange.responseBody());
        assertFalse(exchange.toString().contains(token), "token leaked");
    }

    @Test
    void hookBodyRedactsTokenEverywhereAndKeepsNumbersExact() {
        String body = "{\"fhirAuthorization\":{\"access_token\":\"tok-164\",\"expires_in\":300},"
                + "\"context\":{\"copy\":\"tok-164\",\"price\":1.10,\"big\":1E+2,\"n\":12345678901234567890}}";

        ExchangeSender.HookBody safe = ExchangeSender.redactFhirAuthorization(body);

        assertEquals("tok-164", safe.accessToken());
        assertEquals("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\",\"expires_in\":300},"
                + "\"context\":{\"copy\":\"[REDACTED]\",\"price\":1.10,\"big\":1E+2,\"n\":12345678901234567890}}",
                safe.body());
    }

    @Test
    void nonTextOrEmptyTokenIsStillReplaced() {
        assertEquals(new ExchangeSender.HookBody("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"}}", null),
                ExchangeSender.redactFhirAuthorization("{\"fhirAuthorization\":{\"access_token\":{\"k\":\"tok-164\"}}}"));
        assertEquals(new ExchangeSender.HookBody("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"},\"x\":\"\"}", null),
                ExchangeSender.redactFhirAuthorization("{\"fhirAuthorization\":{\"access_token\":\"\"},\"x\":\"\"}"));
    }

    @Test
    void tokenNeedingJsonEscapesIsRedactedFromRequestAndEchoedResponse() throws Exception {
        String token = "tok\"164\\x";
        String sent = "{\"fhirAuthorization\":{\"access_token\":\"tok\\\"164\\\\x\"}}";
        server.createContext("/cds-services/x", e -> TestResponses.respond(e, 200,
                "{\"echo\":\"tok\\\"164\\\\x\",\"raw\":\"" + token.replace("\"", "") + "\"}"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services/x"))
                .timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofString(sent)).build();

        send(request, sent, PayerCallPhase.HOOK);

        PayerExchange exchange = exchanges.get(0);
        assertEquals("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"}}", exchange.requestBody());
        assertEquals("{\"echo\":\"[REDACTED]\",\"raw\":\"tok164\\x\"}", exchange.responseBody());
        assertFalse(exchange.toString().contains("164\\\\x"), exchange.toString());
    }

    @Test
    void escapedSlashAndTrailingBackslashEchoesAreRedactedWhole() throws Exception {
        // #229 review: JSON may write "/" as "\/", and a raw match must not eat the start of an escaped one.
        String token = "a/b\\";
        String sent = "{\"fhirAuthorization\":{\"access_token\":\"a/b\\\\\"}}";
        String echo = "{\"slash\":\"a\\/b\\\\\",\"plain\":\"a/b\\\\\",\"raw\":\"x " + token.replace("\\", "") + "\"}";
        server.createContext("/cds-services/x", e -> TestResponses.respond(e, 200, echo));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services/x"))
                .timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofString(sent)).build();

        send(request, sent, PayerCallPhase.HOOK);

        PayerExchange exchange = exchanges.get(0);
        assertEquals("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"}}", exchange.requestBody());
        assertEquals("{\"slash\":\"[REDACTED]\",\"plain\":\"[REDACTED]\",\"raw\":\"x a/b\"}", exchange.responseBody());
        new com.fasterxml.jackson.databind.ObjectMapper().readTree(exchange.responseBody());
    }

    @Test
    void tokenInKeysAndEscapedValuesIsRedactedAfterDecoding() {
        String body = "{\"fhirAuthorization\":{\"access_token\":\"t/k\"},\"context\":{\"t\\/k\":[\"x t\\u002fk\",1,{\"t/k\":2}]}}";

        assertEquals("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"},"
                        + "\"context\":{\"[REDACTED]\":[\"x [REDACTED]\",1,{\"[REDACTED]\":2}]}}",
                ExchangeSender.redactFhirAuthorization(body).body());
    }

    @Test
    void jsonResponseWithoutTheTokenKeepsItsBytes() throws Exception {
        String reply = "{ \"cards\" : [ ],\n \"n\":1.50 }";
        hookWithResponse("t/k", 200, reply);

        assertEquals(reply, exchanges.get(0).responseBody());
    }

    @Test
    void nonJsonResponseIsRedactedOrOmittedWhenATokenSpellingSurvives() throws Exception {
        hookWithResponse("t/k", 502, "<html>t/k and t\\/k \\q \\u00zz end\\</html>");
        assertEquals("<html>[REDACTED] and [REDACTED] \\q \\u00zz end\\</html>", exchanges.get(0).responseBody());

        exchanges.clear();
        hookWithResponse("t/k", 502, "<html>t\\u002fk</html>");
        assertNull(exchanges.get(0).responseBody());
    }

    @Test
    void tokenAfterACompleteJsonValueIsRedacted() throws Exception {
        hookWithResponse("t/k", 200, "{\"cards\":[]} trailing t/k");

        assertEquals("{\"cards\":[]} trailing [REDACTED]", exchanges.get(0).responseBody());
    }

    @Test
    void tokenInAnOverwrittenDuplicateKeyIsRedacted() throws Exception {
        hookWithResponse("t/k", 400, "{\"error\":\"t\\/k\",\"error\":\"ok\"}");

        assertFalse(ExchangeSender.looselyDecoded(String.valueOf(exchanges.get(0).responseBody())).contains("t/k"),
                exchanges.get(0).responseBody());
    }

    @Test
    void transportErrorEchoingTheTokenIsRedactedForTheListenerOnly() throws Exception {
        String token = "tok-164-status-line";
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            Thread payer = new Thread(() -> {
                try (Socket client = socket.accept()) {
                    client.getInputStream().read(new byte[8192]);
                    client.getOutputStream().write(("HTTP/1.1 2x0 " + token + "\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
                    client.getOutputStream().flush();
                } catch (IOException ignored) {
                    // The client may close first.
                }
            });
            payer.start();
            String sent = "{\"fhirAuthorization\":{\"access_token\":\"" + token + "\"}}";
            HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + socket.getLocalPort() + "/cds-services/x"))
                    .timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofString(sent)).build();

            IOException thrown = assertThrows(IOException.class, () -> ExchangeSender.send(HttpClient.newHttpClient(),
                    request, sent, record(), PayerCallPhase.HOOK, 1, exchanges::add));
            payer.join(5000);

            assertTrue(chain(thrown).contains(token), "the caller keeps the original: " + chain(thrown));
            PayerExchange exchange = exchanges.get(0);
            assertInstanceOf(IOException.class, exchange.error());
            assertFalse(exchange.toString().contains(token), exchange.toString());
            assertFalse(chain(exchange.error()).contains(token), chain(exchange.error()));
        }
    }

    @Test
    void safeErrorKeepsTheKindAndDropsTheToken() {
        IOException clean = new IOException("connection reset");
        assertSame(clean, ExchangeSender.safeError(clean, "t/k", false));
        assertSame(clean, ExchangeSender.safeError(clean, null, false));
        assertNull(ExchangeSender.safeError(null, "t/k", true));

        assertSafe(new java.net.http.HttpConnectTimeoutException("t/k"), java.net.http.HttpConnectTimeoutException.class);
        assertSafe(new java.net.http.HttpTimeoutException("x t/k"), java.net.http.HttpTimeoutException.class);
        assertSafe(new InterruptedException("t\\/k"), InterruptedException.class);
        IOException wrapped = new IOException("outer", new IllegalStateException("t/k"));
        assertSafe(wrapped, IOException.class);
        IOException suppressed = new IOException("outer");
        suppressed.addSuppressed(new IOException("t/k"));
        suppressed.addSuppressed(suppressed.getSuppressed()[0]);
        assertSafe(suppressed, IOException.class);

        Exception unreadable = ExchangeSender.safeError(new java.net.http.HttpTimeoutException("anything"), null, true);
        assertEquals("java.net.http.HttpTimeoutException: [message omitted]", unreadable.getMessage());
        assertEquals(java.net.http.HttpTimeoutException.class, unreadable.getClass());
    }

    @Test
    void safeErrorFindsARawTokenThatDecodingWouldHide() {
        // A backslash right before the token turns its first character into an escape when decoded.
        Exception safe = ExchangeSender.safeError(new IOException("status \\tok-164"), "tok-164", false);

        assertFalse(chain(safe).contains("tok-164"), chain(safe));
    }

    private static void assertSafe(Exception error, Class<?> kind) {
        Exception safe = ExchangeSender.safeError(error, "t/k", false);
        assertEquals(kind, safe.getClass());
        assertNull(safe.getCause());
        assertFalse(ExchangeSender.looselyDecoded(chain(safe)).contains("t/k"), chain(safe));
        assertTrue(safe.getMessage().startsWith(error.getClass().getName() + ": "), safe.getMessage());
    }

    @Test
    void safeHookFailureBranches() throws Exception {
        server.createContext("/fail", e -> {
            e.getResponseHeaders().add("X-Echo", "t/k");
            TestResponses.respond(e, 503, "t/k");
        });
        java.net.http.HttpResponse<String> response = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder(URI.create(base + "/fail")).GET().build(),
                java.net.http.HttpResponse.BodyHandlers.ofString());

        ExchangeSender.SafeFailure none = ExchangeSender.safeHookFailure(response, "t/k", "{\"hook\":\"x\"}");
        assertSame(response, none.response());
        assertEquals("t/k", none.body());

        ExchangeSender.SafeFailure known = ExchangeSender.safeHookFailure(response, "t/k",
                "{\"fhirAuthorization\":{\"access_token\":\"t/k\"}}");
        assertEquals(List.of("[REDACTED]"), known.response().headers().allValues("X-Echo"));
        assertEquals("[REDACTED]", known.body());

        ExchangeSender.SafeFailure unreadable = ExchangeSender.safeHookFailure(response, "t/k", "{");
        java.net.http.HttpResponse<String> kept = unreadable.response();
        assertNull(unreadable.body());
        assertTrue(kept.headers().map().isEmpty());
        assertEquals(503, kept.statusCode());
        assertSame(response.request(), kept.request());
        assertEquals(response.uri(), kept.uri());
        assertEquals(response.version(), kept.version());
        assertEquals(response.sslSession(), kept.sslSession());
        assertTrue(kept.previousResponse().isEmpty());
        assertNull(kept.body());
    }

    private static String chain(Throwable error) {
        StringBuilder out = new StringBuilder();
        for (Throwable t = error; t != null; t = t.getCause()) {
            out.append(t).append(" | ");
        }
        return out.toString();
    }

    @Test
    void looseDecodingHandlesEveryEscape() {
        assertEquals("\"\\/\b\f\n\r\tA\\x\\u12", ExchangeSender.looselyDecoded("\\\"\\\\\\/\\b\\f\\n\\r\\t\\u0041\\x\\u12"));
        assertEquals("end\\", ExchangeSender.looselyDecoded("end\\"));
    }

    private void hookWithResponse(String token, int status, String reply) throws Exception {
        String path = "/cds-services/r" + exchanges.size() + status + reply.length();
        server.createContext(path, e -> TestResponses.respond(e, status, reply));
        String sent = "{\"fhirAuthorization\":{\"access_token\":\"" + token + "\"}}";
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + path))
                .timeout(Duration.ofSeconds(5)).POST(HttpRequest.BodyPublishers.ofString(sent)).build();
        send(request, sent, PayerCallPhase.HOOK);
    }

    @Test
    void discoveryBodiesPassThrough() throws Exception {
        server.createContext("/cds-services", e -> TestResponses.respond(e, 200, "{\"services\":[]}"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services"))
                .timeout(Duration.ofSeconds(5)).GET().build();

        send(request, null, PayerCallPhase.DISCOVERY);

        assertEquals("{\"services\":[]}", exchanges.get(0).responseBody());
        assertEquals(null, exchanges.get(0).requestBody());
    }

    private void send(HttpRequest request, String body, PayerCallPhase phase) throws Exception {
        ConnectionRecord record = record();
        ExchangeSender.send(HttpClient.newHttpClient(), request, body, record, phase, 1, exchanges::add);
        assertEquals(1, exchanges.size());
    }

    private ConnectionRecord record() {
        return ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).credentialRef("credential")
                .clientId("client").tokenEndpoint(base + "/token").build();
    }
}
