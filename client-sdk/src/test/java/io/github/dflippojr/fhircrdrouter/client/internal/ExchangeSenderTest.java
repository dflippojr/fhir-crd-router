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
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;

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
        assertEquals(new ExchangeSender.HookBody("{\"fhirAuthorization\":{\"access_token\":\"[REDACTED]\"},\"x\":\"\"}", ""),
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
    void discoveryBodiesPassThrough() throws Exception {
        server.createContext("/cds-services", e -> TestResponses.respond(e, 200, "{\"services\":[]}"));
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/cds-services"))
                .timeout(Duration.ofSeconds(5)).GET().build();

        send(request, null, PayerCallPhase.DISCOVERY);

        assertEquals("{\"services\":[]}", exchanges.get(0).responseBody());
        assertEquals(null, exchanges.get(0).requestBody());
    }

    private void send(HttpRequest request, String body, PayerCallPhase phase) throws Exception {
        ConnectionRecord record = ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).credentialRef("credential")
                .clientId("client").tokenEndpoint(base + "/token").build();
        ExchangeSender.send(HttpClient.newHttpClient(), request, body, record, phase, 1, exchanges::add);
        assertEquals(1, exchanges.size());
    }
}
