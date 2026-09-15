package io.github.dflippojr.fhircrdrouter.client.auth;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class OAuth2TokenClientTest {

    private HttpServer server;
    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final AtomicReference<String> expiresInJson = new AtomicReference<>(",\"expires_in\":300");
    private final AtomicReference<String> lastAuthorization = new AtomicReference<>();
    private final MutableClock clock = new MutableClock(Instant.parse("2026-01-01T00:00:00Z"));
    private OAuth2TokenClient tokenClient;

    @BeforeEach
    void startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("localhost", 0), 0);
        server.createContext("/token", exchange -> {
            int n = tokenRequests.incrementAndGet();
            lastAuthorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            byte[] bytes = ("{\"access_token\":\"token-" + n + "\",\"token_type\":\"Bearer\"" + expiresInJson.get() + "}")
                    .getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (var os = exchange.getResponseBody()) {
                os.write(bytes);
            }
        });
        server.start();
        tokenClient = new OAuth2TokenClient(HttpClient.newHttpClient(), clock);
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void reusesTokenUntilJustBeforeExpiry() {
        ConnectionRecord record = record(List.of("crd"));

        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));
        clock.advance(Duration.ofSeconds(300).minus(OAuth2TokenClient.EXPIRY_SKEW).minusSeconds(1));
        assertEquals("token-1", tokenClient.fetchAccessToken(record, "secret"));

        clock.advance(Duration.ofSeconds(1));
        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
        assertEquals(2, tokenRequests.get());
    }

    @Test
    void doesNotCacheTokenWithoutExpiresIn() {
        expiresInJson.set("");
        ConnectionRecord record = record(List.of());

        tokenClient.fetchAccessToken(record, "secret");
        tokenClient.fetchAccessToken(record, "secret");

        assertEquals(2, tokenRequests.get());
    }

    @Test
    void invalidateForcesRefetch() {
        ConnectionRecord record = record(List.of());

        tokenClient.fetchAccessToken(record, "secret");
        tokenClient.invalidate(record);

        assertEquals("token-2", tokenClient.fetchAccessToken(record, "secret"));
    }

    @Test
    void cachesSeparatelyPerClientIdAndScopes() {
        String a = tokenClient.fetchAccessToken(record("client-a", List.of("crd")), "secret");
        String b = tokenClient.fetchAccessToken(record("client-b", List.of("crd")), "secret");
        String c = tokenClient.fetchAccessToken(record("client-a", List.of("other")), "secret");

        assertNotEquals(a, b);
        assertNotEquals(a, c);
        assertEquals(3, tokenRequests.get());
    }

    @Test
    void sendsFormEncodedClientSecretBasicCredentials() {
        tokenClient.fetchAccessToken(record("client id", List.of()), "p@ss:word");

        String decoded = new String(Base64.getDecoder().decode(lastAuthorization.get().substring("Basic ".length())),
                StandardCharsets.UTF_8);
        assertEquals("client+id:p%40ss%3Aword", decoded);
    }

    @Test
    void recordRequiresClientIdForOAuth2() {
        assertThrows(IllegalArgumentException.class, () -> record(null, List.of()));
    }

    private ConnectionRecord record(List<String> scopes) {
        return record("client", scopes);
    }

    private ConnectionRecord record(String clientId, List<String> scopes) {
        return ConnectionRecord.builder()
                .payerId("PAYER-OAUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("http://localhost:" + server.getAddress().getPort())
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("http://localhost:" + server.getAddress().getPort() + "/token")
                .clientId(clientId)
                .scopes(scopes)
                .credentialRef("ref")
                .build();
    }

    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration duration) {
            now = now.plus(duration);
        }

        @Override public Instant instant() { return now; }
        @Override public ZoneOffset getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
    }
}
