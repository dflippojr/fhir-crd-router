package io.github.dflippo.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippo.fhircrdrouter.core.AuthType;
import io.github.dflippo.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippo.fhircrdrouter.core.CredentialProvider;
import io.github.dflippo.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CdsHooksClientTest {

    private HttpServer server;
    private ConnectionRecord record;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);

        server.createContext("/cds-services", exchange -> {
            String body = """
                    {"services":[{"hook":"patient-view","title":"Example Hook","description":"desc","id":"example-hook"}]}""";
            sendJson(exchange, body);
        });

        server.createContext("/cds-services/example-hook", exchange -> {
            String body = """
                    {"cards":[{"summary":"Prior auth required","indicator":"warning"}]}""";
            sendJson(exchange, body);
        });

        server.start();

        record = ConnectionRecord.builder()
                .payerId("PAYER-TEST")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort())
                .authType(AuthType.NONE)
                .build();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void discoversServices() {
        CdsHooksClient client = new CdsHooksClient(noopCredentialProvider());

        List<CdsServiceDescriptor> services = client.discoverServices(record);

        assertEquals(1, services.size());
        assertEquals("example-hook", services.get(0).id());
        assertEquals("patient-view", services.get(0).hook());
    }

    @Test
    void callsHookAndParsesCards() {
        CdsHooksClient client = new CdsHooksClient(noopCredentialProvider());

        CdsHookResponse response = client.callHook(record, "example-hook",
                new CdsHookRequest("patient-view", "instance-1", Map.of(), Map.of()));

        assertEquals(1, response.cards().size());
        assertEquals("Prior auth required", response.cards().get(0).summary());
        assertTrue(response.rawJson().has("cards"));
    }

    private static void sendJson(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static CredentialProvider noopCredentialProvider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }
}
