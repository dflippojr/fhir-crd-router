package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Received;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Whatever credential the client sends on an attempt, for every {@link AuthType} and every phase it
 * reaches, a payer that echoes it back in an error body cannot get it into a {@link PayerCallException}:
 * not whole, and not as a prefix of 8 or more characters left where the body is cut at 4096 bytes (#195).
 * The echo is taken from what arrived on the wire, so a new auth type or credential is covered once
 * {@link #record} builds it.
 */
class EchoedCredentialPropertiesTest {

    /** Fixed so CI is reproducible; jqwik prints the seed and the shrunk sample on failure. */
    private static final String SEED = "195";
    private static final int BODY_LIMIT = 4096;
    private static final int WINDOW = 8;
    private static final String TOKEN_ERROR_LEAD = "{\"error\":\"invalid_client\",\"error_description\":\"";
    private static final String SIGNING_KEY = TestKeys.privateKeyPem(TestKeys.ec("secp384r1"));
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final CredentialProvider CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String ref) {
            return Optional.of(ref.equals("signing-key") ? SIGNING_KEY : "synthetic-" + ref);
        }
        @Override public void put(String ref, String value) { }
        @Override public void remove(String ref) { }
    };
    private static final CdsHookRequest REQUEST = new CdsHookRequest("order-sign", "instance", Map.of(), Map.of());

    private static LoopbackPayer payer;

    @BeforeContainer
    static void start() {
        payer = new LoopbackPayer();
    }

    @AfterContainer
    static void stop() {
        payer.close();
    }

    /**
     * {@code permille} places the 4096-byte cut along the credential: 0 cuts just before it, and
     * values near 1000 keep all of it, so most tries straddle the boundary.
     */
    @Property(seed = SEED, tries = 300)
    void echoedCredentialNeverSurvivesInTheException(@ForAll("authTypes") AuthType authType,
                                                     @ForAll PayerCallPhase phase,
                                                     @ForAll("errorStatuses") int status,
                                                     @ForAll @IntRange(max = 1000) int permille) {
        boolean oauth = authType == AuthType.OAUTH2_CLIENT_CREDENTIALS || authType == AuthType.OAUTH2_PRIVATE_KEY_JWT;
        Assume.that(phase != PayerCallPhase.TOKEN || oauth);
        List<String> echoed = new CopyOnWriteArrayList<>();
        payer.reset(request -> {
            if (request.rawPath().equals("/token") && phase != PayerCallPhase.TOKEN) {
                return new Reply(200, "{\"access_token\":\"synthetic-token-" + UUID.randomUUID() + "\"}");
            }
            String credential = credentialIn(request);
            echoed.add(credential);
            String lead = request.rawPath().equals("/token") ? TOKEN_ERROR_LEAD : "";
            int cut = permille * (credential.length() + 16) / 1000;
            String echo = "x".repeat(Math.max(0, BODY_LIMIT - lead.length() - cut)) + credential;
            return new Reply(status, lead.isEmpty() ? echo + " tail" : lead + echo + "\"}");
        });
        ConnectionRecord record = record(authType);
        CdsHooksClient client = new CdsHooksClient(HTTP, CREDENTIALS);

        PayerCallException error = assertThrows(PayerCallException.class, () -> {
            if (phase == PayerCallPhase.HOOK) {
                client.callHookRaw(record, "svc", REQUEST);
            } else {
                client.discoverServices(record);
            }
        });

        assertEquals(phase, error.phase());
        assertFalse(echoed.isEmpty());
        for (String credential : echoed) {
            for (int i = 0; i + WINDOW <= credential.length(); i++) {
                String window = credential.substring(i, i + WINDOW);
                assertFalse(error.responseBody().contains(window), () -> "responseBody kept " + window);
                assertFalse(error.getMessage().contains(window), () -> "getMessage kept " + window);
                assertFalse(error.toString().contains(window), () -> "toString kept " + window);
            }
        }
    }

    /** The credential as the server received it: a bearer token, a Basic client secret or a client assertion. */
    private static String credentialIn(Received request) {
        String authorization = request.authorization();
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring("Bearer ".length());
        }
        if (authorization != null && authorization.startsWith("Basic ")) {
            String pair = new String(Base64.getDecoder().decode(authorization.substring("Basic ".length())),
                    StandardCharsets.UTF_8);
            return URLDecoder.decode(pair.substring(pair.indexOf(':') + 1), StandardCharsets.UTF_8);
        }
        for (String field : request.body().split("&")) {
            if (field.startsWith("client_assertion=")) {
                return URLDecoder.decode(field.substring("client_assertion=".length()), StandardCharsets.UTF_8);
            }
        }
        throw new AssertionError("no credential in " + request);
    }

    /** Exhaustive over {@link AuthType}, so a new auth type does not compile until it is covered here. */
    private static ConnectionRecord record(AuthType authType) {
        String origin = payer.origin();
        var builder = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX).baseUrl(origin)
                .authType(authType);
        return switch (authType) {
            case NONE -> builder.build();
            case API_KEY -> builder.credentialRef("api-key").build();
            case OAUTH2_CLIENT_CREDENTIALS -> builder.tokenEndpoint(origin + "/token").clientId("client")
                    .credentialRef("client-secret").build();
            case OAUTH2_PRIVATE_KEY_JWT -> builder.tokenEndpoint(origin + "/token").clientId("client")
                    .keyId("key-1").credentialRef("signing-key").build();
            case CDS_HOOKS_JWT -> builder.clientId("client").keyId("key-1").credentialRef("signing-key").build();
        };
    }

    @Provide
    Arbitrary<AuthType> authTypes() {
        // NONE sends no credential, so there is nothing to echo.
        return Arbitraries.of(AuthType.class).filter(type -> type != AuthType.NONE);
    }

    @Provide
    Arbitrary<Integer> errorStatuses() {
        return Arbitraries.of(400, 401, 403, 500);
    }
}
