package io.github.dflippojr.fhircrdrouter.client.internal;

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

    private void send(HttpRequest request, String body, PayerCallPhase phase) throws Exception {
        ConnectionRecord record = ConnectionRecord.builder().payerId("payer").environment(Environment.SANDBOX)
                .baseUrl(base).authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).credentialRef("credential")
                .clientId("client").tokenEndpoint(base + "/token").build();
        ExchangeSender.send(HttpClient.newHttpClient(), request, body, record, phase, 1, exchanges::add);
        assertEquals(1, exchanges.size());
    }
}
