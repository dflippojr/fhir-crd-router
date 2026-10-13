package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditedCredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** OAuth2 secrets are resolved only when a token request is actually sent. */
class CdsHooksClientLazySecretTest {

    private static final CdsHookRequest REQUEST =
            new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of());

    private HttpServer server;
    private ExecutorService serverThreads;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicReference<String> revokedToken = new AtomicReference<>();
    private volatile long tokenDelayMillis;
    private final Map<String, String> secrets = new ConcurrentHashMap<>();
    private final AtomicInteger resolves = new AtomicInteger();

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverThreads = Executors.newCachedThreadPool();
        server.setExecutor(serverThreads);
        server.createContext("/token", exchange -> {
            int n = tokenRequests.incrementAndGet();
            if (tokenDelayMillis > 0) {
                try {
                    Thread.sleep(tokenDelayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
            respond(exchange, 200, "{\"access_token\":\"token-" + n + "\",\"expires_in\":300}");
        });
        server.createContext("/cds-services/order-sign-crd", exchange -> {
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            boolean revoked = auth == null || auth.equals("Bearer " + revokedToken.get());
            respond(exchange, revoked ? 401 : 200, "{\"cards\":[]}");
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
        serverThreads.shutdownNow();
    }

    @ParameterizedTest
    @EnumSource(value = AuthType.class, names = {"OAUTH2_CLIENT_CREDENTIALS", "OAUTH2_PRIVATE_KEY_JWT"})
    void warmCallsDoNotResolveSecretAndRefreshAfter401ResolvesOnce(AuthType authType) throws Exception {
        ConnectionRecord record = record(authType, "oauth-secret");
        secrets.put("oauth-secret", secretFor(authType));
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), countingProvider());

        client.callHook(record, "order-sign-crd", REQUEST);
        assertEquals(1, resolves.get());

        for (int i = 0; i < 10; i++) {
            client.callHook(record, "order-sign-crd", REQUEST);
        }
        assertEquals(1, resolves.get());
        assertEquals(1, tokenRequests.get());

        revokedToken.set("token-1");
        client.callHook(record, "order-sign-crd", REQUEST);
        assertEquals(2, resolves.get());
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void warmCallsRecordNoCredentialResolveAuditEvents() {
        secrets.put("oauth-secret", "synthetic-secret");
        List<String> actions = new CopyOnWriteArrayList<>();
        AuditSink sink = (c, action, k, t, env, o, f) -> {
            actions.add(action);
            return null;
        };
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(),
                new AuditedCredentialProvider(countingProvider(), sink));
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS, "oauth-secret");

        client.callHook(record, "order-sign-crd", REQUEST);
        assertEquals(List.of("credential.resolve.found"), actions);
        actions.clear();

        for (int i = 0; i < 10; i++) {
            client.callHook(record, "order-sign-crd", REQUEST);
        }
        assertTrue(actions.stream().noneMatch(a -> a.startsWith("credential.resolve.")), actions.toString());
    }

    @Test
    void concurrentColdCallersResolveSecretOnce() throws Exception {
        tokenDelayMillis = 50;
        secrets.put("oauth-secret", "synthetic-secret");
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), countingProvider());
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS, "oauth-secret");
        int callers = 32;
        ExecutorService pool = Executors.newFixedThreadPool(callers);
        try {
            CountDownLatch start = new CountDownLatch(1);
            List<Future<CdsHookResponse>> futures = new ArrayList<>();
            for (int i = 0; i < callers; i++) {
                futures.add(pool.submit(() -> {
                    start.await();
                    return client.callHook(record, "order-sign-crd", REQUEST);
                }));
            }
            start.countDown();
            for (Future<CdsHookResponse> f : futures) {
                f.get(10, TimeUnit.SECONDS);
            }
        } finally {
            pool.shutdownNow();
        }
        assertEquals(1, tokenRequests.get());
        assertEquals(1, resolves.get());
    }

    @Test
    void missingCredentialRefOnColdCacheFailsWithSameMessage() {
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS, null);
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), countingProvider());

        RouterException error = assertThrows(RouterException.class,
                () -> client.callHook(record, "order-sign-crd", REQUEST));
        assertEquals("authType=OAUTH2_CLIENT_CREDENTIALS but no credentialRef set for payerId=PAYER-LAZY",
                error.getMessage());
        assertEquals(0, tokenRequests.get());
    }

    @Test
    void missingSecretOnColdCacheFailsWithSameMessage() {
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS, "absent");
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), countingProvider());

        RouterException error = assertThrows(RouterException.class,
                () -> client.callHook(record, "order-sign-crd", REQUEST));
        assertEquals("No credential found for ref=absent (payerId=PAYER-LAZY)", error.getMessage());
        assertEquals(0, tokenRequests.get());
    }

    private ConnectionRecord record(AuthType authType, String credentialRef) {
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return ConnectionRecord.builder()
                .payerId("PAYER-LAZY").environment(Environment.SANDBOX).baseUrl(base)
                .authType(authType).tokenEndpoint(base + "/token")
                .clientId("synthetic-client").keyId("key-1").credentialRef(credentialRef).build();
    }

    private static String secretFor(AuthType authType) throws Exception {
        return authType == AuthType.OAUTH2_PRIVATE_KEY_JWT
                ? TestKeys.privateKeyPem(TestKeys.ec("secp384r1"))
                : "synthetic-secret";
    }

    private CredentialProvider countingProvider() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) {
                resolves.incrementAndGet();
                return Optional.ofNullable(secrets.get(ref));
            }
            @Override public void put(String ref, String value) { secrets.put(ref, value); }
            @Override public void remove(String ref) { secrets.remove(ref); }
        };
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        TestResponses.respond(exchange, status, body);
    }
}
