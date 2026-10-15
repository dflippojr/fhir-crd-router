package io.github.dflippojr.fhircrdrouter.client;

import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditPersistenceException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditedCredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.audit.JsonlAuditTrail;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.time.Clock;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalInt;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class ConnectionVerificationTest {
    private static final String CATALOG = """
            {"services":[
              {"id":"sign-check","hook":"order-sign","description":"Synthetic order-sign service"},
              {"id":"select-check","hook":"order-select","description":"Synthetic order-select service"}]}""";

    private HttpServer server;
    private final AtomicInteger discoveryCalls = new AtomicInteger();
    private final AtomicInteger otherCalls = new AtomicInteger();
    private final List<PayerExchange> exchanges = new ArrayList<>();
    private final CountDownLatch release = new CountDownLatch(1);
    private String body = CATALOG;
    private int status = 200;
    private boolean block;
    private String secret = "synthetic-secret";

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/cds-services", e -> {
            if (!e.getRequestURI().getPath().equals("/cds-services")) {
                otherCalls.incrementAndGet();
                TestResponses.respond(e, 404, "{}");
                return;
            }
            discoveryCalls.incrementAndGet();
            if (block) {
                try {
                    release.await();
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                e.close();
                return;
            }
            e.getResponseHeaders().add("Retry-After", "0");
            e.getResponseHeaders().add("X-Request-Id", "HEADER-MARKER");
            TestResponses.respond(e, status, body);
        });
        server.start();
    }

    @AfterEach
    void stop() {
        release.countDown();
        server.stop(0);
    }

    @Test
    void validCatalogReportsHooksAndMakesOnlyTheDiscoveryExchange() {
        Instant before = Instant.now();
        ConnectionVerification report = client().verify(connection(AuthType.API_KEY));

        assertTrue(report.ok());
        assertEquals("PAYER-SYNTHETIC", report.payerId());
        assertEquals(Environment.SANDBOX, report.environment());
        assertFalse(report.checkedAt().isBefore(before));
        assertFalse(report.checkedAt().isAfter(Instant.now()));
        assertFalse(report.elapsed().isNegative());
        assertEquals(2, report.serviceCount());
        assertEquals(List.of("order-select", "order-sign"), List.copyOf(report.hooks()));
        assertTrue(report.findings().isEmpty());
        assertTrue(report.failurePhase().isEmpty());
        assertTrue(report.failureStatus().isEmpty());
        assertEquals("", report.failureReason());
        assertThrows(UnsupportedOperationException.class, () -> report.hooks().add("order-dispatch"));

        assertEquals(1, discoveryCalls.get());
        assertEquals(0, otherCalls.get());
        assertEquals(List.of(PayerCallPhase.DISCOVERY), exchanges.stream().map(PayerExchange::phase).toList());
    }

    @Test
    void emptyObjectReportsValidatorFindingWithoutFailurePhase() {
        body = "{}";
        ConnectionVerification report = client().verify(connection(AuthType.NONE));

        assertFalse(report.ok());
        assertEquals(List.of("services"), report.findings().stream().map(CdsDiscoveryValidator.Violation::path).toList());
        assertTrue(report.failurePhase().isEmpty());
        assertTrue(report.failureStatus().isEmpty());
        assertEquals(0, report.serviceCount());
        assertTrue(report.hooks().isEmpty());
        assertFalse(report.failureReason().isEmpty());
    }

    @Test
    void invalidEntriesStillReportCountAndUsableHooks() {
        body = "{\"services\":[{\"id\":\"a\",\"hook\":\"order-sign\",\"description\":\"d\"},"
                + "{\"id\":\"b\",\"hook\":\"order-sign\"},{\"hook\":7}]}";
        ConnectionVerification report = client().verify(connection(AuthType.NONE));

        assertFalse(report.ok());
        assertEquals(3, report.serviceCount());
        assertEquals(Set.of("order-sign"), report.hooks());
        assertEquals(4, report.findings().size());
    }

    @Test
    void discovery401WithoutOAuthIsReported() {
        status = 401;
        assertFailure(client().verify(connection(AuthType.API_KEY)), PayerCallPhase.DISCOVERY, 401,
                "discovery request returned HTTP 401");
        assertEquals(1, discoveryCalls.get());
    }

    @Test
    void discovery500IsReported() {
        status = 500;
        assertFailure(client().verify(connection(AuthType.NONE)), PayerCallPhase.DISCOVERY, 500,
                "discovery request returned HTTP 500");
    }

    @Test
    void refusedConnectionIsReported() throws IOException {
        int closedPort;
        try (ServerSocket socket = new ServerSocket(0)) {
            closedPort = socket.getLocalPort();
        }
        ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-SYNTHETIC")
                .environment(Environment.SANDBOX).baseUrl("http://127.0.0.1:" + closedPort).build();

        ConnectionVerification report = client().verify(record);

        assertFailure(report, PayerCallPhase.DISCOVERY, null, "discovery request transport failure");
        assertEquals(1, exchanges.size());
    }

    @Test
    void timeoutIsReported() {
        block = true;
        CdsHooksClient client = new CdsHooksClient(credentials(), Duration.ofMillis(50),
                Duration.ofSeconds(2), exchanges::add);
        assertFailure(client.verify(connection(AuthType.NONE)), PayerCallPhase.DISCOVERY, null,
                "discovery request timed out");
    }

    @Test
    void tokenEndpoint400IsReportedAsTokenFailure() {
        server.createContext("/token", e -> TestResponses.respond(e, 400, "{\"error\":\"invalid_client\"}"));
        ConnectionVerification report = client().verify(connection(AuthType.OAUTH2_CLIENT_CREDENTIALS));

        assertFailure(report, PayerCallPhase.TOKEN, 400, "token request returned HTTP 400");
        assertEquals(0, discoveryCalls.get());
        assertEquals(List.of(PayerCallPhase.TOKEN), exchanges.stream().map(PayerExchange::phase).toList());
    }

    @Test
    void missingCredentialIsReportedWithoutAnyExchange() {
        secret = null;
        assertFailure(client().verify(connection(AuthType.API_KEY)), PayerCallPhase.DISCOVERY, null,
                "missing credential for discovery request");
        assertFailure(client().verify(connection(AuthType.OAUTH2_CLIENT_CREDENTIALS)), PayerCallPhase.TOKEN, null,
                "missing credential for token request");
        ConnectionRecord noRef = ConnectionRecord.builder().payerId("PAYER-SYNTHETIC")
                .environment(Environment.SANDBOX).baseUrl(baseUrl()).authType(AuthType.API_KEY).build();
        assertFailure(client().verify(noRef), PayerCallPhase.DISCOVERY, null,
                "missing credential for discovery request");
        ConnectionRecord noCert = ConnectionRecord.builder().payerId("PAYER-SYNTHETIC")
                .environment(Environment.SANDBOX).baseUrl(baseUrl()).mtlsCredentialRef("cert").build();
        assertFailure(client().verify(noCert), PayerCallPhase.DISCOVERY, null,
                "missing credential for discovery request");
        assertTrue(exchanges.isEmpty());
        assertEquals(0, discoveryCalls.get());
    }

    @Test
    void providerFailureIsReportedByTypeOnly() {
        ConnectionRecord noPhase = ConnectionRecord.builder().payerId("PAYER-SYNTHETIC")
                .environment(Environment.SANDBOX).baseUrl(baseUrl()).mtlsCredentialRef("cert").build();
        for (RuntimeException failure : List.of(new IllegalStateException("MESSAGE-MARKER"),
                new UncheckedIOException("MESSAGE-MARKER", new IOException("MESSAGE-MARKER")))) {
            CdsHooksClient failing = new CdsHooksClient(failingCredentials(failure), Duration.ofSeconds(2),
                    Duration.ofSeconds(2), exchanges::add);
            String type = failure.getClass().getSimpleName();
            assertCredentialFailure(failing.verify(connection(AuthType.OAUTH2_CLIENT_CREDENTIALS)),
                    PayerCallPhase.TOKEN, type);
            assertCredentialFailure(failing.verify(keyed(AuthType.OAUTH2_PRIVATE_KEY_JWT)),
                    PayerCallPhase.TOKEN, type);
            assertCredentialFailure(failing.verify(connection(AuthType.API_KEY)), PayerCallPhase.DISCOVERY, type);
            assertCredentialFailure(failing.verify(keyed(AuthType.CDS_HOOKS_JWT)),
                    PayerCallPhase.DISCOVERY, type);
            assertCredentialFailure(failing.verify(noPhase), PayerCallPhase.DISCOVERY, type);
        }
        assertTrue(exchanges.isEmpty());
        assertEquals(0, discoveryCalls.get());
    }

    @Test
    void providerFailureOnOtherCallsIsWrappedAsRouterExceptionWithCause() {
        IllegalStateException failure = new IllegalStateException("Failed to decrypt credential");
        CdsHooksClient failing = new CdsHooksClient(failingCredentials(failure));
        ConnectionRecord record = connection(AuthType.API_KEY);

        RouterException thrown = assertThrows(RouterException.class, () -> failing.discoverServices(record));
        assertSame(failure, thrown.getCause());
        assertFalse(thrown.getMessage().contains("decrypt"));
        assertSame(failure, assertThrows(RouterException.class, () -> failing.discoverServicesRaw(record)).getCause());
        assertSame(failure, assertThrows(RouterException.class, () -> failing.callHook(record, "order-sign",
                new CdsHookRequest("order-sign", "instance-1", java.util.Map.of(), java.util.Map.of()))).getCause());
    }

    @Test
    void auditPersistenceFailurePropagatesFromVerify(@TempDir Path dir) throws IOException {
        secret = "synthetic-secret";
        JsonlAuditTrail trail = new JsonlAuditTrail(dir.resolve("audit.jsonl"), Clock.systemUTC());
        trail.close();
        CdsHooksClient audited = new CdsHooksClient(new AuditedCredentialProvider(credentials(), trail));

        assertThrows(AuditPersistenceException.class, () -> audited.verify(connection(AuthType.API_KEY)));
        assertEquals(0, discoveryCalls.get());
    }

    @Test
    void unusableCredentialIsReportedByTypeOnly() {
        secret = "not-a-pem-SECRET-MARKER";
        ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-SYNTHETIC")
                .environment(Environment.SANDBOX).baseUrl(baseUrl()).authType(AuthType.CDS_HOOKS_JWT)
                .clientId("synthetic-client").keyId("k1").credentialRef("synthetic").build();

        ConnectionVerification report = client().verify(record);

        assertFalse(report.ok());
        assertTrue(report.failurePhase().isEmpty());
        assertEquals("connection could not be verified: IllegalArgumentException", report.failureReason());
        assertFalse(report.toString().contains("SECRET-MARKER"));
    }

    @Test
    void unparseableBodyIsReportedWithoutItsContent() {
        body = "not-json BODY-MARKER";
        assertFailure(client().verify(connection(AuthType.NONE)), PayerCallPhase.DISCOVERY, 200,
                "discovery response is not valid JSON");
    }

    @Test
    void reportNeverContainsResponseBodyHeadersOrCredential() {
        status = 403;
        body = "{\"detail\":\"BODY-MARKER\"}";
        secret = "AUTH-MARKER";
        ConnectionVerification report = client().verify(connection(AuthType.API_KEY));

        assertFailure(report, PayerCallPhase.DISCOVERY, 403, "discovery request returned HTTP 403");
        assertEquals("Bearer [REDACTED]", exchanges.get(0).requestHeaders().firstValue("Authorization").orElseThrow());
        for (String text : List.of(report.failureReason(), report.toString())) {
            for (String marker : List.of("BODY-MARKER", "AUTH-MARKER", "HEADER-MARKER", "synthetic")) {
                assertFalse(text.contains(marker), marker + " leaked into " + text);
            }
        }
    }

    @Test
    void nullArgumentsThrow() {
        assertThrows(NullPointerException.class, () -> client().verify(null));
    }

    @Test
    void successfulReportCannotCarryFindingsOrFailure() {
        Instant now = Instant.now();
        var finding = new CdsDiscoveryValidator.Violation(CdsDiscoveryValidator.Severity.ERROR, "services", "m");
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVerification("p", Environment.SANDBOX,
                now, Duration.ZERO, true, new TreeSet<>(), 0, List.of(finding), Optional.empty(),
                OptionalInt.empty(), ""));
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVerification("p", Environment.SANDBOX,
                now, Duration.ZERO, true, new TreeSet<>(), 0, List.of(), Optional.of(PayerCallPhase.DISCOVERY),
                OptionalInt.empty(), ""));
        assertThrows(IllegalArgumentException.class, () -> new ConnectionVerification("p", Environment.SANDBOX,
                now, Duration.ZERO, false, new TreeSet<>(), -1, List.of(), Optional.empty(),
                OptionalInt.empty(), "x"));
    }

    private static void assertFailure(ConnectionVerification report, PayerCallPhase phase, Integer status,
                                      String reason) {
        assertFalse(report.ok());
        assertEquals(Optional.of(phase), report.failurePhase());
        assertEquals(status == null ? OptionalInt.empty() : OptionalInt.of(status), report.failureStatus());
        assertEquals(reason, report.failureReason());
        assertTrue(report.findings().isEmpty());
        assertTrue(report.hooks().isEmpty());
        assertFalse(report.elapsed().isNegative());
    }

    private ConnectionRecord keyed(AuthType auth) {
        return ConnectionRecord.builder().payerId("PAYER-SYNTHETIC").environment(Environment.SANDBOX)
                .baseUrl(baseUrl()).authType(auth).credentialRef("synthetic-ref").clientId("synthetic-client")
                .keyId("k1").tokenEndpoint(baseUrl() + "/token").build();
    }

    private static void assertCredentialFailure(ConnectionVerification report, PayerCallPhase phase, String type) {
        assertFailure(report, phase, null, "credential could not be read: " + type);
        assertFalse(report.toString().contains("MESSAGE-MARKER"));
    }

    private static CredentialProvider failingCredentials(RuntimeException failure) {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { throw failure; }
            @Override public void put(String ref, String value) { }
            @Override public void remove(String ref) { }
        };
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private ConnectionRecord connection(AuthType auth) {
        return ConnectionRecord.builder().payerId("PAYER-SYNTHETIC").environment(Environment.SANDBOX)
                .baseUrl(baseUrl() + "/").authType(auth).credentialRef("synthetic-ref")
                .clientId("synthetic-client").tokenEndpoint(baseUrl() + "/token").build();
    }

    private CredentialProvider credentials() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.ofNullable(secret); }
            @Override public void put(String ref, String value) { }
            @Override public void remove(String ref) { }
        };
    }

    private CdsHooksClient client() {
        return new CdsHooksClient(credentials(), Duration.ofSeconds(2), Duration.ofSeconds(2), exchanges::add);
    }
}
