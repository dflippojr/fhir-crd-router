package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.FailingHttpClient;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.http.HttpClient;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@code baseUrl}, {@code tokenEndpoint} and {@code jwksUrl} must be absolute https URLs with a host;
 * plain http is allowed only to a loopback host (#156). CDS Hooks 2.0, Security and Safety
 * (https://cds-hooks.hl7.org/2.0/#security-and-safety): data "MUST be transmitted over channels secured
 * using ... TLS". A refused URL fails before any credential is read or any request is sent.
 */
class CdsHooksClientUrlSchemeTest {

    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "i", Map.of(), null);

    @TempDir
    Path tempDir;

    /** Every reference the client asked the provider for, mTLS bundles included. */
    private final List<String> resolved = new CopyOnWriteArrayList<>();

    @ParameterizedTest
    @CsvSource({
            "API_KEY, false",
            "API_KEY, true",
            "OAUTH2_CLIENT_CREDENTIALS, false",
            "OAUTH2_CLIENT_CREDENTIALS, true",
    })
    void refusesCleartextBaseUrlBeforeAnyRequest(AuthType authType, boolean mtls) {
        ConnectionRecord record = record(authType, "http://payer.example/r4", "https://auth.example/token", mtls);
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        EndpointUrlException e = assertThrows(EndpointUrlException.class, () -> client.discoverServices(record));

        assertEquals("baseUrl", e.field());
        assertEquals("PAYER-156", e.payerId());
        assertTrue(e.getMessage().contains("baseUrl"), e.getMessage());
        assertTrue(e.getMessage().contains("payerId=PAYER-156"), e.getMessage());
        assertTrue(resolved.isEmpty(), "credentials resolved: " + resolved);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void refusesCleartextTokenEndpointBeforeAnyRequest(boolean mtls) {
        ConnectionRecord record = record(AuthType.OAUTH2_CLIENT_CREDENTIALS, "https://payer.example/r4",
                "http://auth.example/token", mtls);
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        for (Executable call : calls(client, record)) {
            EndpointUrlException e = assertThrows(EndpointUrlException.class, call);
            assertEquals("tokenEndpoint", e.field());
            assertTrue(e.getMessage().contains("tokenEndpoint"), e.getMessage());
            assertTrue(e.getMessage().contains("payerId=PAYER-156"), e.getMessage());
        }
        assertTrue(resolved.isEmpty(), "credentials resolved: " + resolved);
    }

    @Test
    void refusesCleartextJwksUrlBeforeSigning() {
        ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-156").environment(Environment.SANDBOX)
                .baseUrl("https://payer.example/r4").authType(AuthType.CDS_HOOKS_JWT).clientId("ehr")
                .keyId("k1").jwksUrl("http://ehr.example/jwks.json").credentialRef("signing-key").build();
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        for (Executable call : calls(client, record)) {
            EndpointUrlException e = assertThrows(EndpointUrlException.class, call);
            assertEquals("jwksUrl", e.field());
        }
        assertTrue(resolved.isEmpty(), "credentials resolved: " + resolved);
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://127.0.0.1", "http://localhost", "http://LOCALHOST", "http://127.5.6.7",
            "http://[::1]", "http://[0:0:0:0:0:0:0:1]"})
    void allowsLoopbackHttp(String loopbackOrigin) throws Exception {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(r -> new Reply(200, "{\"services\":[]}"));
            String port = payer.origin().substring(payer.origin().lastIndexOf(':'));
            ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-156")
                    .environment(Environment.PRODUCTION).baseUrl(loopbackOrigin + port).authType(AuthType.NONE)
                    .build();
            CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), recordingCredentials());

            if (loopbackOrigin.contains("127.0.0.1")) {
                assertEquals(List.of(), client.discoverServices(record));
                assertEquals(1, payer.received().size());
            } else {
                // The payer listens on 127.0.0.1 only, so these hosts may fail to connect, but only on the wire.
                try {
                    client.discoverServices(record);
                } catch (PayerCallException transport) {
                    assertTrue(transport.statusCode().isEmpty());
                }
            }
        }
    }

    @Test
    void allowsLoopbackHttpTokenEndpoint() {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(r -> r.rawPath().equals("/token")
                    ? new Reply(200, "{\"access_token\":\"t\",\"expires_in\":60}")
                    : new Reply(200, "{\"services\":[]}"));
            ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-156")
                    .environment(Environment.PRODUCTION).baseUrl(payer.origin())
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).clientId("c").credentialRef("secret")
                    .tokenEndpoint(payer.origin() + "/token").build();

            new CdsHooksClient(HttpClient.newHttpClient(), recordingCredentials()).discoverServices(record);

            assertEquals(List.of("/token", "/cds-services"),
                    payer.received().stream().map(LoopbackPayer.Received::rawPath).toList());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"http://localhost.evil.example/r4", "http://127.0.0.1.evil.example/r4",
            "http://evil.example.localhost.example/r4", "http://127.0.0.1.nip.io/r4", "http://0.0.0.0/r4",
            "http://10.0.0.1/r4", "http://[::2]/r4", "HTTP://payer.example/r4"})
    void refusesHostsThatOnlyLookLikeLoopback(String baseUrl) {
        ConnectionRecord record = record(AuthType.NONE, baseUrl, null, false);
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        for (Executable call : calls(client, record)) {
            EndpointUrlException e = assertThrows(EndpointUrlException.class, call);
            assertEquals("baseUrl", e.field());
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://payer example/r4", "payer.example/r4", "ftp://payer.example/r4",
            "https:///r4", "https:payer.example", "mailto:payer@example.org", "//payer.example/r4", "",
            "https://payer_example/r4"})
    void malformedUrlsFailWithRouterException(String baseUrl) {
        ConnectionRecord record = record(AuthType.API_KEY, baseUrl, null, true);
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        for (Executable call : calls(client, record)) {
            EndpointUrlException e = assertThrows(EndpointUrlException.class, call);
            assertEquals("baseUrl", e.field());
            assertTrue(e.getMessage().contains("payerId=PAYER-156"), e.getMessage());
        }
        assertTrue(resolved.isEmpty(), "credentials resolved: " + resolved);
    }

    /**
     * The SDK appends {@code /cds-services} to {@code baseUrl} (CDS Hooks 2.0, Discovery:
     * https://cds-hooks.hl7.org/2.0/#discovery). After a query or fragment that suffix lands in the query or
     * is dropped, so the request would go to the base path itself instead of the discovery or service URL.
     */
    @ParameterizedTest
    @ValueSource(strings = {"https://payer.example/r4?tenant=SECRET-TENANT", "https://payer.example/r4?",
            "https://payer.example/r4#SECRET-TENANT", "https://payer.example/r4/?tenant=SECRET-TENANT",
            "http://127.0.0.1/r4?tenant=SECRET-TENANT"})
    void refusesBaseUrlWithQueryOrFragment(String baseUrl) {
        ConnectionRecord record = record(AuthType.API_KEY, baseUrl, null, false);
        CdsHooksClient client = new CdsHooksClient(new FailingHttpClient(), recordingCredentials());

        for (Executable call : calls(client, record)) {
            EndpointUrlException e = assertThrows(EndpointUrlException.class, call);
            assertEquals("baseUrl", e.field());
            assertTrue(e.getMessage().contains("query or fragment"), e.getMessage());
            assertFalse(e.getMessage().contains("SECRET-TENANT"), e.getMessage());
        }
        assertTrue(resolved.isEmpty(), "credentials resolved: " + resolved);
    }

    @Test
    void tokenEndpointMayCarryAQuery() {
        try (LoopbackPayer payer = new LoopbackPayer()) {
            payer.reset(r -> r.rawPath().equals("/token")
                    ? new Reply(200, "{\"access_token\":\"t\",\"expires_in\":60}")
                    : new Reply(200, "{\"services\":[]}"));
            ConnectionRecord record = ConnectionRecord.builder().payerId("PAYER-156")
                    .environment(Environment.PRODUCTION).baseUrl(payer.origin())
                    .authType(AuthType.OAUTH2_CLIENT_CREDENTIALS).clientId("c").credentialRef("secret")
                    .tokenEndpoint(payer.origin() + "/token?tenant=t1").build();

            new CdsHooksClient(HttpClient.newHttpClient(), recordingCredentials()).discoverServices(record);

            assertEquals(List.of("/token", "/cds-services"),
                    payer.received().stream().map(LoopbackPayer.Received::rawPath).toList());
        }
    }

    @Test
    void messageDoesNotEchoTheUrl() {
        ConnectionRecord record = record(AuthType.NONE, "http://user:pw-SECRET@payer.example/r4?key=SECRET", null,
                false);

        EndpointUrlException e = assertThrows(EndpointUrlException.class,
                () -> new CdsHooksClient(new FailingHttpClient(), recordingCredentials()).discoverServices(record));

        assertFalse(e.getMessage().contains("SECRET"), e.getMessage());
    }

    @Test
    void httpsRecordsStillReachTheHttpClient() {
        FailingHttpClient http = new FailingHttpClient();
        ConnectionRecord record = record(AuthType.NONE, "https://payer.example/r4", null, false);

        AssertionError e = assertThrows(AssertionError.class,
                () -> new CdsHooksClient(http, recordingCredentials()).discoverServices(record));

        assertTrue(e.getMessage().contains("https://payer.example/r4/cds-services"), e.getMessage());
    }

    private static List<Executable> calls(CdsHooksClient client, ConnectionRecord record) {
        return List.of(
                () -> client.discoverServices(record),
                () -> client.discoverServicesRaw(record),
                () -> client.callHook(record, "svc", REQUEST),
                () -> client.callHookRaw(record, "svc", REQUEST));
    }

    private static ConnectionRecord record(AuthType authType, String baseUrl, String tokenEndpoint, boolean mtls) {
        return ConnectionRecord.builder().payerId("PAYER-156").environment(Environment.PRODUCTION)
                .baseUrl(baseUrl).authType(authType).credentialRef("api").clientId("client")
                .tokenEndpoint(tokenEndpoint).mtlsCredentialRef(mtls ? "mtls" : null).build();
    }

    private CredentialProvider recordingCredentials() {
        return new CredentialProvider() {
            @Override
            public Optional<String> resolve(String credentialRef) {
                resolved.add(credentialRef);
                return Optional.of(credentialRef.equals("mtls")
                        ? TestKeys.selfSigned(tempDir, "synthetic-mtls").pemBundle() : "s3cret");
            }
            @Override public void put(String credentialRef, String secretValue) { }
            @Override public void remove(String credentialRef) { }
        };
    }
}
