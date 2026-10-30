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
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CdsHooksClientTest {

    private HttpServer server;
    private ConnectionRecord record;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger securedHookCalls = new AtomicInteger();
    private final List<String> requestPaths = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);

        server.createContext("/cds-services", exchange -> {
            requestPaths.add(exchange.getRequestURI().getRawPath());
            String body = """
                    {"services":[{"hook":"order-sign","title":"Example Hook","description":"desc","id":"example-hook"}]}""";
            sendJson(exchange, body);
        });

        server.createContext("/cds-services/example-hook", exchange -> {
            requestPaths.add(exchange.getRequestURI().getRawPath());
            String body = """
                    {"cards":[{"summary":"Prior auth required","indicator":"warning"}]}""";
            sendJson(exchange, body);
        });

        server.createContext("/token", exchange -> sendJson(exchange,
                "{\"access_token\":\"token-" + tokenRequests.incrementAndGet() + "\",\"expires_in\":300}"));

        server.createContext("/cds-services/broken-hook", exchange -> sendJson(exchange, "not-json"));

        // Rejects the first token it sees (simulating early revocation), accepts later ones.
        server.createContext("/cds-services/secured-hook", exchange -> {
            securedHookCalls.incrementAndGet();
            if ("Bearer token-1".equals(exchange.getRequestHeaders().getFirst("Authorization"))) {
                exchange.sendResponseHeaders(401, -1);
                exchange.close();
                return;
            }
            sendJson(exchange, "{\"cards\":[]}");
        });

        // Always rejects, to prove the client retries only once.
        server.createContext("/cds-services/always-401", exchange -> {
            securedHookCalls.incrementAndGet();
            exchange.sendResponseHeaders(401, -1);
            exchange.close();
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
        assertEquals("order-sign", services.get(0).hook());
    }

    @Test
    void callsHookAndParsesCards() {
        CdsHooksClient client = new CdsHooksClient(noopCredentialProvider());

        CdsHookResponse response = client.callHook(record, "example-hook",
                new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of()));

        assertEquals(1, response.cards().size());
        assertEquals("Prior auth required", response.cards().get(0).summary());
        assertTrue(response.rawJson().has("cards"));
    }

    @Test
    void hookCallReportsAnUnparseableBodyWithItsCause() {
        CdsHooksClient client = new CdsHooksClient(noopCredentialProvider());
        CdsHookRequest request = new CdsHookRequest("order-sign", "instance-4", Map.of(), Map.of());

        for (var call : List.<Executable>of(
                () -> client.callHookRaw(record, "broken-hook", request),
                () -> client.callHook(record, "broken-hook", request))) {
            RouterException error = assertThrows(RouterException.class, call);
            assertEquals("Hook call for payerId=PAYER-TEST serviceId=broken-hook returned an unparseable body",
                    error.getMessage());
            assertInstanceOf(IOException.class, error.getCause());
        }
    }

    @Test
    void baseUrlWithTrailingSlashKeepsOneSlashBeforeCdsServices() {
        CdsHooksClient client = new CdsHooksClient(noopCredentialProvider());
        ConnectionRecord slashed = ConnectionRecord.builder()
                .payerId("PAYER-TEST")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort() + "/")
                .authType(AuthType.NONE)
                .build();

        client.discoverServices(slashed);
        client.discoverServicesRaw(slashed);
        client.callHook(slashed, "example-hook", new CdsHookRequest("order-sign", "instance-5", Map.of(), Map.of()));

        assertEquals(List.of("/cds-services", "/cds-services", "/cds-services/example-hook"), requestPaths);
    }

    @Test
    void oauth2RetriesOnceWithFreshTokenAfter401() {
        CdsHooksClient client = new CdsHooksClient(fixedCredentialProvider("secret"));

        client.callHook(oauthRecord(), "secured-hook",
                new CdsHookRequest("order-sign", "instance-2", Map.of(), Map.of()));

        assertEquals(2, tokenRequests.get());
        assertEquals(2, securedHookCalls.get());
    }

    @Test
    void oauth2GivesUpAfterSingleRetry() {
        CdsHooksClient client = new CdsHooksClient(fixedCredentialProvider("secret"));

        assertThrows(io.github.dflippojr.fhircrdrouter.core.RouterException.class, () -> client.callHook(oauthRecord(),
                "always-401", new CdsHookRequest("order-sign", "instance-3", Map.of(), Map.of())));
        assertEquals(2, securedHookCalls.get());
    }

    private ConnectionRecord oauthRecord() {
        String base = "http://localhost:" + server.getAddress().getPort();
        return ConnectionRecord.builder()
                .payerId("PAYER-OAUTH")
                .environment(Environment.SANDBOX)
                .baseUrl(base)
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(base + "/token")
                .clientId("client")
                .credentialRef("payer-oauth")
                .build();
    }

    private static CredentialProvider fixedCredentialProvider(String secret) {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of(secret); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }

    private static void sendJson(com.sun.net.httpserver.HttpExchange exchange, String body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        TestResponses.respond(exchange, 200, body);
    }

    private static CredentialProvider noopCredentialProvider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }
}
