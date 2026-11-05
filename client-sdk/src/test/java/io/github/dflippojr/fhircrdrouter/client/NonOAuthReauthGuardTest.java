package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Pins the auth-type conjunct of the 401 re-auth condition in {@code CdsHooksClient.send}
 * ({@code status == 401 && record.authType().usesOAuth2Token() && freshToken == null && !reauthenticated}) on its
 * own (#224). An ordinary hook call on a connection without an OAuth2 token has no token to drop and refresh, so
 * a 401 is the result: one payer request, no token exchange, and a later 200 is never seen.
 *
 * <p>The three types are named rather than filtered with {@code !usesOAuth2Token()}, so the test does not lean on
 * the predicate it pins. Each record also sets a {@code tokenEndpoint} on the same loopback server, so a stray
 * token exchange would be counted.
 */
class NonOAuthReauthGuardTest {

    private static final String EMPTY_RESPONSE = "{\"cards\":[]}";
    private static final CdsHookRequest REQUEST =
            new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of());

    private HttpServer server;
    private final Map<String, String> secrets = new HashMap<>();

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @ParameterizedTest
    @EnumSource(value = AuthType.class, names = {"NONE", "API_KEY", "CDS_HOOKS_JWT"})
    void ordinaryCallOnNonOAuthConnectionDoesNotReauthenticateAfter401(AuthType authType) throws Exception {
        AtomicInteger hookRequests = new AtomicInteger();
        AtomicInteger tokenRequests = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/cds-services/order-sign-crd", exchange -> {
            if (hookRequests.incrementAndGet() == 1) {
                respond(exchange, 401, "{\"error\":\"unauthorized\"}");
            } else {
                respond(exchange, 200, EMPTY_RESPONSE);
            }
        });
        server.createContext("/token", exchange -> {
            tokenRequests.incrementAndGet();
            respond(exchange, 200, "{\"access_token\":\"stray\",\"expires_in\":300}");
        });
        server.start();

        ConnectionRecord record = record(authType, base);
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), credentials());

        PayerCallException failure = assertThrows(PayerCallException.class,
                () -> client.callHook(record, "order-sign-crd", REQUEST));

        assertEquals(OptionalInt.of(401), failure.statusCode());
        assertEquals(1, hookRequests.get(), "hook requests");
        assertEquals(0, tokenRequests.get(), "token requests");
    }

    private ConnectionRecord record(AuthType authType, String base) throws Exception {
        ConnectionRecord.Builder builder = ConnectionRecord.builder()
                .payerId("PAYER-" + authType).environment(Environment.SANDBOX).baseUrl(base)
                .authType(authType).tokenEndpoint(base + "/token");
        switch (authType) {
            case NONE -> { }
            case API_KEY -> {
                secrets.put("api-key", "synthetic-api-key");
                builder.credentialRef("api-key");
            }
            case CDS_HOOKS_JWT -> {
                secrets.put("signing-key", TestKeys.privateKeyPem(TestKeys.ec("secp384r1")));
                builder.clientId("ehr-client").keyId("key-1").credentialRef("signing-key");
            }
            default -> throw new IllegalArgumentException("not a non-OAuth type under test: " + authType);
        }
        return builder.build();
    }

    private CredentialProvider credentials() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.ofNullable(secrets.get(ref)); }
            @Override public void put(String ref, String value) { secrets.put(ref, value); }
            @Override public void remove(String ref) { secrets.remove(ref); }
        };
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        TestResponses.respond(exchange, status, body);
    }
}
