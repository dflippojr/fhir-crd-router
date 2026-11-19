package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.io.IOException;
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

    private LoopbackPayer payer;
    private ConnectionRecord record;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicInteger securedHookCalls = new AtomicInteger();
    private final List<String> requestPaths = new CopyOnWriteArrayList<>();

    @BeforeEach
    void startServer() {
        payer = new LoopbackPayer();

        payer.on("/cds-services", request -> {
            requestPaths.add(request.rawPath());
            String body = """
                    {"services":[{"hook":"order-sign","title":"Example Hook","description":"desc","id":"example-hook"}]}""";
            return new Reply(200, body);
        });

        payer.on("/cds-services/example-hook", request -> {
            requestPaths.add(request.rawPath());
            String body = """
                    {"cards":[{"summary":"Prior auth required","indicator":"warning"}]}""";
            return new Reply(200, body);
        });

        payer.on("/token", request -> new Reply(200,
                "{\"access_token\":\"token-" + tokenRequests.incrementAndGet() + "\",\"expires_in\":300}"));

        payer.on("/cds-services/broken-hook", new Reply(200, "not-json"));

        // Rejects the first token it sees (simulating early revocation), accepts later ones.
        payer.on("/cds-services/secured-hook", request -> {
            securedHookCalls.incrementAndGet();
            if ("Bearer token-1".equals(request.authorization())) {
                return Reply.empty(401);
            }
            return new Reply(200, "{\"cards\":[]}");
        });

        // Always rejects, to prove the client retries only once.
        payer.on("/cds-services/always-401", request -> {
            securedHookCalls.incrementAndGet();
            return Reply.empty(401);
        });

        record = TestRecords.none(payer).payerId("PAYER-TEST").build();
    }

    @AfterEach
    void stopServer() {
        payer.close();
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
        ConnectionRecord slashed = TestRecords.forAuth(AuthType.NONE, payer.url("/")).payerId("PAYER-TEST").build();

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
        return TestRecords.oauth2(payer).payerId("PAYER-OAUTH").build();
    }

    private static CredentialProvider fixedCredentialProvider(String secret) {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of(secret); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }

    private static CredentialProvider noopCredentialProvider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }
}
