package io.github.dflippojr.fhircrdrouter.client;

import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsExchange;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** End-to-end auth tests: real HTTP(S) servers verifying what the client actually sends. */
class CdsHooksClientAuthTest {

    private static final String EMPTY_RESPONSE = "{\"cards\":[]}";
    private static final CdsHookRequest REQUEST =
            new CdsHookRequest("order-sign", "instance-1", Map.of(), Map.of());

    @TempDir
    Path tempDir;

    private HttpServer server;
    private final Map<String, String> secrets = new HashMap<>();

    @AfterEach
    void stop() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void cdsHooksJwtIsSignedPerRequestWithExactServiceUrlAsAudience() throws Exception {
        KeyPair keys = TestKeys.ec("secp384r1");
        secrets.put("signing-key", TestKeys.privateKeyPem(keys));
        AtomicReference<String> failure = new AtomicReference<>();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/cds-services/order-sign-crd", exchange -> {
            try {
                SignedJWT jwt = SignedJWT.parse(bearer(exchange));
                if (!jwt.verify(new ECDSAVerifier((ECPublicKey) keys.getPublic()))) {
                    failure.set("signature did not verify");
                } else if (!jwt.getJWTClaimsSet().getAudience().equals(List.of(base + "/cds-services/order-sign-crd"))) {
                    failure.set("wrong aud " + jwt.getJWTClaimsSet().getAudience());
                } else if (!"ehr-client".equals(jwt.getJWTClaimsSet().getIssuer())) {
                    failure.set("wrong iss");
                }
            } catch (Exception e) {
                failure.set(e.toString());
            }
            respond(exchange, failure.get() == null ? 200 : 401, EMPTY_RESPONSE);
        });
        server.start();

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-CDS-JWT").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.CDS_HOOKS_JWT).clientId("ehr-client").keyId("key-1")
                .credentialRef("signing-key").build();

        new CdsHooksClient(HttpClient.newHttpClient(), credentials()).callHook(record, "order-sign-crd", REQUEST);

        assertNull(failure.get());
    }

    @Test
    void privateKeyJwtSendsClientAssertionInsteadOfBasicAuth() throws Exception {
        KeyPair keys = TestKeys.ec("secp384r1");
        secrets.put("signing-key", TestKeys.privateKeyPem(keys));
        AtomicReference<String> failure = new AtomicReference<>();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        server.createContext("/token", exchange -> {
            Map<String, String> form = parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            try {
                SignedJWT assertion = SignedJWT.parse(form.get("client_assertion"));
                if (exchange.getRequestHeaders().containsKey("Authorization")) {
                    failure.set("must not send Basic auth with private_key_jwt");
                } else if (!"urn:ietf:params:oauth:client-assertion-type:jwt-bearer".equals(form.get("client_assertion_type"))) {
                    failure.set("wrong client_assertion_type");
                } else if (!assertion.verify(new ECDSAVerifier((ECPublicKey) keys.getPublic()))) {
                    failure.set("assertion signature did not verify");
                } else if (!assertion.getJWTClaimsSet().getAudience().equals(List.of(base + "/token"))) {
                    failure.set("wrong assertion aud");
                }
            } catch (Exception e) {
                failure.set(e.toString());
            }
            respond(exchange, 200, "{\"access_token\":\"granted\",\"expires_in\":300}");
        });
        server.createContext("/cds-services/order-sign-crd", exchange ->
                respond(exchange, "granted".equals(bearer(exchange)) ? 200 : 401, EMPTY_RESPONSE));
        server.start();

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-PKJWT").environment(Environment.SANDBOX).baseUrl(base)
                .authType(AuthType.OAUTH2_PRIVATE_KEY_JWT).tokenEndpoint(base + "/token")
                .clientId("ehr-client").keyId("key-1").credentialRef("signing-key").build();

        new CdsHooksClient(HttpClient.newHttpClient(), credentials()).callHook(record, "order-sign-crd", REQUEST);

        assertNull(failure.get());
    }

    @Test
    void mutualTlsPresentsClientCertificateAlongsideAppLayerAuth() throws Exception {
        TestKeys.Identity serverId = TestKeys.selfSigned(tempDir, "payer-server");
        TestKeys.Identity clientId = TestKeys.selfSigned(tempDir, "ehr-client");
        secrets.put("client-cert", clientId.pemBundle());
        secrets.put("api-key", "k-123");
        AtomicReference<String> seenPeer = new AtomicReference<>();
        AtomicReference<String> seenAuth = new AtomicReference<>();

        startHttpsServer(serverId, clientId, exchange -> {
            X509Certificate peer = (X509Certificate) ((HttpsExchange) exchange).getSSLSession().getPeerCertificates()[0];
            seenPeer.set(peer.getSubjectX500Principal().getName());
            seenAuth.set(exchange.getRequestHeaders().getFirst("Authorization"));
            respond(exchange, 200, EMPTY_RESPONSE);
        });

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-MTLS").environment(Environment.SANDBOX)
                .baseUrl("https://127.0.0.1:" + server.getAddress().getPort())
                .authType(AuthType.API_KEY).credentialRef("api-key")
                .mtlsCredentialRef("client-cert").build();

        new CdsHooksClient(HttpClient.newHttpClient(), credentials(), serverId.trustStore())
                .callHook(record, "order-sign-crd", REQUEST);

        assertEquals("CN=ehr-client", seenPeer.get());
        assertEquals("Bearer k-123", seenAuth.get());
    }

    @Test
    void serverRequiringMutualTlsRejectsClientWithoutCertificate() throws Exception {
        TestKeys.Identity serverId = TestKeys.selfSigned(tempDir, "payer-server");
        TestKeys.Identity clientId = TestKeys.selfSigned(tempDir, "ehr-client");
        startHttpsServer(serverId, clientId, exchange -> respond(exchange, 200, EMPTY_RESPONSE));

        SSLContext trustOnly = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(serverId.trustStore());
        trustOnly.init(null, tmf.getTrustManagers(), null);

        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-MTLS").environment(Environment.SANDBOX)
                .baseUrl("https://127.0.0.1:" + server.getAddress().getPort())
                .authType(AuthType.NONE).build();

        CdsHooksClient client = new CdsHooksClient(HttpClient.newBuilder().sslContext(trustOnly).build(), credentials());
        assertThrows(RouterException.class, () -> client.callHook(record, "order-sign-crd", REQUEST));
    }

    @Test
    void missingMtlsCredentialFailsClearly() {
        ConnectionRecord record = ConnectionRecord.builder()
                .payerId("PAYER-MTLS").environment(Environment.SANDBOX).baseUrl("https://127.0.0.1:1")
                .authType(AuthType.NONE).mtlsCredentialRef("absent").build();

        RouterException error = assertThrows(RouterException.class,
                () -> new CdsHooksClient(credentials()).callHook(record, "x", REQUEST));
        assertTrue(error.getMessage().contains("No mTLS credential"), error.getMessage());
    }

    private void startHttpsServer(TestKeys.Identity serverId, TestKeys.Identity trustedClient,
                                  com.sun.net.httpserver.HttpHandler handler) throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverId.keyStore(), TestKeys.Identity.password());
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustedClient.trustStore());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpsServer https = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        https.setHttpsConfigurator(new HttpsConfigurator(context) {
            @Override
            public void configure(HttpsParameters params) {
                var parameters = context.getDefaultSSLParameters();
                parameters.setNeedClientAuth(true);
                params.setSSLParameters(parameters);
            }
        });
        https.createContext("/cds-services/order-sign-crd", handler);
        https.start();
        server = https;
    }

    private CredentialProvider credentials() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.ofNullable(secrets.get(ref)); }
            @Override public void put(String ref, String value) { secrets.put(ref, value); }
            @Override public void remove(String ref) { secrets.remove(ref); }
        };
    }

    private static String bearer(HttpExchange exchange) {
        String header = exchange.getRequestHeaders().getFirst("Authorization");
        return header != null && header.startsWith("Bearer ") ? header.substring("Bearer ".length()) : "";
    }

    private static Map<String, String> parseForm(String body) {
        return Arrays.stream(body.split("&"))
                .map(pair -> pair.split("=", 2))
                .collect(Collectors.toMap(p -> p[0], p -> URLDecoder.decode(p.length > 1 ? p[1] : "", StandardCharsets.UTF_8)));
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
