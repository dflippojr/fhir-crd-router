package io.github.dflippojr.fhircrdrouter.client.auth;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.lang.reflect.RecordComponent;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.BrokenBarrierException;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Class-level check for "the token cache key omits a {@link ConnectionRecord} field that changes the
 * token request" (#106, #192). Every record component is either a {@link #KEYED} field, which gets a
 * separate token request, or an {@link #EXCLUDED} field, which has a reason and shares the token. A
 * new component is in neither list, so {@link #everyRecordComponentIsClassified} fails until someone
 * decides which it is.
 */
class OAuth2TokenCacheKeyTest {

    private static final String SECRET_A = "synthetic-secret-a";
    private static final String SECRET_B = "synthetic-secret-b";

    /** A change to one component of the baseline record. */
    private record Variation(String component, String label, UnaryOperator<ConnectionRecord.Builder> vary) {
        @Override public String toString() {
            return component + " " + label;
        }
    }

    /** A component left out of the cache key, with the reason it does not change the token request. */
    private record Excluded(String component, String reason, UnaryOperator<ConnectionRecord.Builder> vary) {
        @Override public String toString() {
            return component;
        }
    }

    private final AtomicInteger tokenRequests = new AtomicInteger();
    private final List<String> authorizations = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private ExecutorService serverThreads;
    private OAuth2TokenClient tokenClient;
    private static String pem;

    private static List<Variation> keyed() {
        return List.of(
                new Variation("tokenEndpoint", "other path",
                        b -> b.tokenEndpoint(b.build().tokenEndpoint() + "-other")),
                new Variation("clientId", "other value", b -> b.clientId("client-other")),
                new Variation("scopes", "other value", b -> b.scopes(List.of("other"))),
                new Variation("scopes", "empty", b -> b.scopes(List.of())),
                new Variation("mtlsCredentialRef", "set", b -> b.mtlsCredentialRef("cert-a")),
                new Variation("credentialRef", "other value", b -> b.credentialRef("ref-b")),
                new Variation("credentialRef", "unset", b -> b.credentialRef(null)),
                new Variation("authType", "private key JWT", b -> b.authType(AuthType.OAUTH2_PRIVATE_KEY_JWT)));
    }

    private static List<Excluded> excluded() {
        return List.of(
                new Excluded("payerId", "labels errors and audit events; a shared client registration is one token",
                        b -> b.payerId("PAYER-OTHER")),
                new Excluded("displayName", "a label for people, never sent",
                        b -> b.displayName("Other name")),
                new Excluded("environment", "not sent; environments differ by endpoint and client ID",
                        b -> b.environment(Environment.PRODUCTION)),
                new Excluded("baseUrl", "where payer calls go, never sent to the token endpoint",
                        b -> b.baseUrl("https://other.example")),
                new Excluded("keyId", "labels the signed assertion and does not choose the credential "
                        + "(DECISIONS.md, \"fetchAccessToken checks jwksUrl first\")",
                        b -> b.keyId("key-other")),
                new Excluded("jwksUrl", "labels the signed assertion and does not choose the credential "
                        + "(DECISIONS.md, \"fetchAccessToken checks jwksUrl first\")",
                        b -> b.jwksUrl("https://other.example/jwks.json")),
                new Excluded("tenant", "a claim of the CDS Hooks JWT, not of the token request",
                        b -> b.tenant("tenant-other")),
                new Excluded("igVersion", "metadata, never sent", b -> b.igVersion("2.2.1")),
                new Excluded("status", "lifecycle metadata, never sent", b -> b.status(ConnectionStatus.INACTIVE)),
                new Excluded("lastVerifiedAt", "changes on every successful verify; must not drop the token",
                        b -> b.lastVerifiedAt(Instant.parse("2026-02-02T00:00:00Z"))),
                new Excluded("contactInfo", "metadata, never sent", b -> b.contactInfo("other@example.test")),
                new Excluded("createdAt", "bookkeeping, never sent", b -> b.createdAt(Instant.EPOCH)),
                new Excluded("updatedAt", "changes on every record save; must not drop the token",
                        b -> b.updatedAt(Instant.EPOCH)));
    }

    @BeforeAll
    static void generateKey() throws Exception {
        pem = TestKeys.privateKeyPem(TestKeys.ec("secp384r1"));
    }

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        serverThreads = Executors.newCachedThreadPool();
        server.setExecutor(serverThreads);
        server.createContext("/token", exchange -> {
            int n = tokenRequests.incrementAndGet();
            authorizations.add(String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")));
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            TestResponses.respond(exchange, 200, "{\"access_token\":\"token-" + n + "\",\"expires_in\":300}");
        });
        server.start();
        tokenClient = new OAuth2TokenClient(HttpClient.newHttpClient());
    }

    @AfterEach
    void stop() {
        server.stop(0);
        serverThreads.shutdownNow();
    }

    @Test
    void everyRecordComponentIsClassified() {
        Set<String> components = Arrays.stream(ConnectionRecord.class.getRecordComponents())
                .map(RecordComponent::getName).collect(Collectors.toCollection(TreeSet::new));
        Set<String> keyedNames = keyed().stream().map(Variation::component).collect(Collectors.toSet());
        Set<String> excludedNames = excluded().stream().map(Excluded::component).collect(Collectors.toSet());

        Set<String> unclassified = new TreeSet<>(components);
        unclassified.removeAll(keyedNames);
        unclassified.removeAll(excludedNames);
        assertEquals(Set.of(), unclassified, "new ConnectionRecord components: add each to keyed() and the "
                + "cache key if it changes the token request, otherwise to excluded() with a reason");

        Set<String> stale = new TreeSet<>(keyedNames);
        stale.addAll(excludedNames);
        stale.removeAll(components);
        assertEquals(Set.of(), stale, "these lists name components ConnectionRecord no longer has");

        Set<String> both = new HashSet<>(keyedNames);
        both.retainAll(excludedNames);
        assertEquals(Set.of(), both, "a component is either keyed or excluded");

        assertEquals(6, keyedNames.size());
        assertEquals(13, excluded().size());
        assertEquals(13, excludedNames.size());
        assertTrue(excluded().stream().noneMatch(e -> e.reason().isBlank()));
    }

    static Stream<Variation> keyedVariations() {
        return keyed().stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("keyedVariations")
    void aKeyedFieldGetsItsOwnTokenRequest(Variation variation) {
        ConnectionRecord base = baseline().build();
        ConnectionRecord varied = variation.vary().apply(baseline()).build();
        server.createContext("/token-other", exchange -> {
            int n = tokenRequests.incrementAndGet();
            TestResponses.respond(exchange, 200, "{\"access_token\":\"token-" + n + "\",\"expires_in\":300}");
        });

        String baseToken = fetch(base);
        String variedToken = fetch(varied);

        assertNotEquals(baseToken, variedToken, "records that differ in " + variation + " shared a token");
        assertEquals(2, tokenRequests.get(), "records that differ in " + variation + " shared a token request");
        assertEquals(baseToken, fetch(base), "the baseline stays cached");
        assertEquals(variedToken, fetch(varied), "the variation is cached under its own key");
        assertEquals(2, tokenRequests.get());
    }

    static Stream<Excluded> excludedComponents() {
        return excluded().stream();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("excludedComponents")
    void anExcludedFieldSharesTheToken(Excluded excluded) {
        String token = fetch(baseline().build());

        assertEquals(token, fetch(excluded.vary().apply(baseline()).build()),
                excluded.component() + " is in the excluded list but changed the cache key");
        assertEquals(1, tokenRequests.get());
    }

    @Test
    void invalidateOnOneCredentialRefKeepsTheOthersToken() {
        ConnectionRecord a = baseline().build();
        ConnectionRecord b = baseline().credentialRef("ref-b").build();
        assertEquals("token-1", tokenClient.fetchAccessToken(a, SECRET_A));
        assertEquals("token-2", tokenClient.fetchAccessToken(b, SECRET_B));

        tokenClient.invalidate(b);

        assertEquals("token-1", tokenClient.fetchAccessToken(a, SECRET_A));
        assertEquals("token-3", tokenClient.fetchAccessToken(b, SECRET_B));
        assertEquals(3, tokenRequests.get());
    }

    /**
     * Each supplier waits at a barrier for the other, which only opens if both fetches are running at
     * once. A caller that joined the other's in-flight fetch never reaches it, and the barrier times out.
     */
    @Test
    void concurrentColdCallersOnDifferentCredentialRefsEachResolveTheirOwnSecret() throws Exception {
        ConnectionRecord a = baseline().build();
        ConnectionRecord b = baseline().credentialRef("ref-b").build();
        CyclicBarrier bothResolving = new CyclicBarrier(2);
        HttpClient http = HttpClient.newHttpClient();
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Future<String> first = pool.submit(() ->
                    tokenClient.fetchAccessToken(http, a, secretAfter(bothResolving, SECRET_A), 1));
            Future<String> second = pool.submit(() ->
                    tokenClient.fetchAccessToken(http, b, secretAfter(bothResolving, SECRET_B), 1));

            assertNotEquals(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
        assertEquals(2, tokenRequests.get());
        assertEquals(Set.of(basic(SECRET_A), basic(SECRET_B)), Set.copyOf(authorizations));
    }

    private static Supplier<String> secretAfter(CyclicBarrier barrier, String secret) {
        return () -> {
            try {
                barrier.await(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException(e);
            } catch (BrokenBarrierException | TimeoutException e) {
                throw new IllegalStateException("the other caller never resolved its own secret", e);
            }
            return secret;
        };
    }

    private static String basic(String secret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                ("client:" + secret).getBytes(StandardCharsets.UTF_8));
    }

    private String fetch(ConnectionRecord record) {
        return tokenClient.fetchAccessToken(record,
                record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT ? pem : SECRET_A);
    }

    private ConnectionRecord.Builder baseline() {
        String origin = "http://127.0.0.1:" + server.getAddress().getPort();
        return ConnectionRecord.builder()
                .payerId("PAYER-KEY")
                .environment(Environment.SANDBOX)
                .baseUrl(origin)
                .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint(origin + "/token")
                .clientId("client")
                .keyId("key-1")
                .scopes(List.of("crd"))
                .credentialRef("ref-a");
    }
}
