package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestResponses;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Malformed payer responses and unsafe service ids must fail cleanly, never as an NPE or a rerouted request. */
class CdsHooksClientInputGuardsTest {

    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "i", Map.of("patientId", "p"), null);

    private HttpServer server;
    private ConnectionRecord record;
    private String base;
    private final List<String> rawRequests = new CopyOnWriteArrayList<>();
    private final AtomicReference<String> responseBody = new AtomicReference<>("{\"cards\":[]}");
    private final AtomicReference<String> authorization = new AtomicReference<>();

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String query = exchange.getRequestURI().getRawQuery();
            rawRequests.add(exchange.getRequestURI().getRawPath() + (query == null ? "" : "?" + query));
            authorization.set(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, responseBody.get());
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
        record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.NONE).build();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "my service|/cds-services/my%20service",
            "svc?x=1#frag|/cds-services/svc%3Fx%3D1%23frag",
            "a/b|/cds-services/a%2Fb",
            "café|/cds-services/caf%C3%A9",
            "50%|/cds-services/50%25",
            "a+b*c~d|/cds-services/a%2Bb%2Ac~d",
            "plain-id_1.v2|/cds-services/plain-id_1.v2",
            "...|/cds-services/...",
    })
    void serviceIdIsSentAsOneEncodedPathSegment(String serviceId, String expectedPath) {
        new CdsHooksClient(noCredentials()).callHook(record, serviceId, REQUEST);

        assertEquals(List.of(expectedPath), rawRequests);
    }

    @ParameterizedTest
    @ValueSource(strings = {"", ".", ".."})
    void unusableServiceIdIsRejectedBeforeAnyRequest(String serviceId) {
        CdsHooksClient client = new CdsHooksClient(noCredentials());

        assertThrows(IllegalArgumentException.class, () -> client.callHook(record, serviceId, REQUEST));
        assertThrows(IllegalArgumentException.class, () -> client.callHookRaw(record, serviceId, REQUEST));
        assertTrue(rawRequests.isEmpty());
    }

    @Test
    void nullServiceIdIsRejectedBeforeAnyRequest() {
        CdsHooksClient client = new CdsHooksClient(noCredentials());

        assertThrows(IllegalArgumentException.class, () -> client.callHook(record, null, REQUEST));
        assertTrue(rawRequests.isEmpty());
    }

    @Test
    void cdsHooksJwtAudienceEqualsTheEncodedRequestUri() throws Exception {
        KeyPair keys = TestKeys.ec("secp384r1");
        String pem = TestKeys.privateKeyPem(keys);
        ConnectionRecord signed = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(base).authType(AuthType.CDS_HOOKS_JWT).clientId("ehr-client").keyId("key-1")
                .credentialRef("signing-key").build();
        CredentialProvider credentials = new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of(pem); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };

        new CdsHooksClient(credentials).callHook(signed, "my service/x", REQUEST);

        SignedJWT jwt = SignedJWT.parse(authorization.get().substring("Bearer ".length()));
        assertEquals(List.of(base + "/cds-services/my%20service%2Fx"), jwt.getJWTClaimsSet().getAudience());
        assertEquals(List.of("/cds-services/my%20service%2Fx"), rawRequests);
    }

    @ParameterizedTest
    @ValueSource(strings = {"cards", "systemActions"})
    void nullEntryIsAMalformedEntryNotAnNpe(String field) {
        responseBody.set("{\"" + field + "\":[null]}");

        RouterException e = assertThrows(RouterException.class,
                () -> new CdsHooksClient(noCredentials()).callHook(record, "s", REQUEST));

        assertTrue(e.getMessage().contains(field), e.getMessage());
        assertTrue(e.getMessage().contains("payerId=P"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"cards", "systemActions"})
    void nonArrayFieldIsRejected(String field) {
        responseBody.set("{\"" + field + "\":{\"summary\":\"x\"}}");

        RouterException e = assertThrows(RouterException.class,
                () -> new CdsHooksClient(noCredentials()).callHook(record, "s", REQUEST));

        assertTrue(e.getMessage().contains(field), e.getMessage());
        assertTrue(e.getMessage().contains("payerId=P"), e.getMessage());
    }

    @Test
    void missingOrNullFieldsStillMeanEmpty() {
        for (String body : List.of("{}", "{\"cards\":null,\"systemActions\":null}")) {
            responseBody.set(body);

            CdsHookResponse response = new CdsHooksClient(noCredentials()).callHook(record, "s", REQUEST);

            assertTrue(response.cards().isEmpty());
            assertTrue(response.systemActions().isEmpty());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "[]", "42", "true", "\"text\"", ""})
    void callHookRejectsANonObjectRoot(String body) {
        responseBody.set(body);

        RouterException e = assertThrows(RouterException.class,
                () -> new CdsHooksClient(noCredentials()).callHook(record, "s", REQUEST));

        assertTrue(e.getMessage().contains("payerId=P"), e.getMessage());
        assertTrue(e.getMessage().contains("not a JSON object"), e.getMessage());
        if (!body.isEmpty()) {
            assertFalse(e.getMessage().contains(body), e.getMessage());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"null", "[]", "42", "true", "\"text\""})
    void callHookRawKeepsANonObjectRoot(String body) throws IOException {
        responseBody.set(body);

        JsonNode raw = new CdsHooksClient(noCredentials()).callHookRaw(record, "s", REQUEST);

        assertEquals(new ObjectMapper().readTree(body), raw);
    }

    @Test
    void callHookRawReturnsAMissingNodeForAnEmptyBody() {
        responseBody.set("");

        JsonNode raw = new CdsHooksClient(noCredentials()).callHookRaw(record, "s", REQUEST);

        assertTrue(raw.isMissingNode(), String.valueOf(raw));
    }

    @Test
    void discoveryNeverReturnsANullDescriptor() {
        responseBody.set("{\"services\":[null]}");

        RouterException e = assertThrows(RouterException.class,
                () -> new CdsHooksClient(noCredentials()).discoverServices(record));

        assertTrue(e.getMessage().contains("payerId=P"), e.getMessage());
    }

    @ParameterizedTest
    @ValueSource(strings = {"k-123\n", "k-123\r\n", "k 123", "k-é", "k-𐀀", "k\u0000"})
    void apiKeyThatIsNotAB64TokenIsRejectedBeforeAnyRequest(String key) {
        ConnectionRecord apiKey = apiKeyRecord();
        CdsHooksClient client = new CdsHooksClient(credentials(key));

        RouterException e = assertThrows(RouterException.class, () -> client.callHook(apiKey, "svc", REQUEST));
        assertThrows(RouterException.class, () -> client.discoverServices(apiKey));

        assertEquals("Credential for ref=api-key (payerId=P) is not a usable bearer token", e.getMessage());
        assertTrue(rawRequests.isEmpty(), "payer called with " + rawRequests);
    }

    @Test
    void b64TokenApiKeyIsSentAsIs() {
        new CdsHooksClient(credentials("Az09-._~+/==")).callHook(apiKeyRecord(), "svc", REQUEST);

        assertEquals("Bearer Az09-._~+/==", authorization.get());
    }

    private ConnectionRecord apiKeyRecord() {
        return ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.API_KEY).credentialRef("api-key").build();
    }

    private static CredentialProvider credentials(String secret) {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.of(secret); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }

    private static CredentialProvider noCredentials() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }

    private static void respond(HttpExchange exchange, String body) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        TestResponses.respond(exchange, 200, body);
    }
}
