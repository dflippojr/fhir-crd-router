package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestRecords;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.net.http.HttpClient;
import java.util.HashMap;
import java.util.List;
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

    /** The hand-rolled server's answer to a path no context matched, so a request no route expects still fails. */
    private static final Reply NOT_FOUND = new Reply(404, "<h1>404 Not Found</h1>No context found for request",
            Map.of("Content-Type", List.of("text/html")));

    private final LoopbackPayer payer = new LoopbackPayer();
    private final Map<String, String> secrets = new HashMap<>();

    @BeforeEach
    void routesOnly() {
        payer.otherwise(request -> NOT_FOUND);
    }

    @AfterEach
    void stop() {
        payer.close();
    }

    @ParameterizedTest
    @EnumSource(value = AuthType.class, names = {"NONE", "API_KEY", "CDS_HOOKS_JWT"})
    void ordinaryCallOnNonOAuthConnectionDoesNotReauthenticateAfter401(AuthType authType) throws Exception {
        AtomicInteger hookRequests = new AtomicInteger();
        AtomicInteger tokenRequests = new AtomicInteger();
        payer.on("/cds-services/order-sign-crd", request -> hookRequests.incrementAndGet() == 1
                ? new Reply(401, "{\"error\":\"unauthorized\"}")
                : new Reply(200, EMPTY_RESPONSE));
        payer.on("/token", request -> {
            tokenRequests.incrementAndGet();
            return new Reply(200, "{\"access_token\":\"stray\",\"expires_in\":300}");
        });

        ConnectionRecord record = record(authType);
        CdsHooksClient client = new CdsHooksClient(HttpClient.newHttpClient(), credentials());

        PayerCallException failure = assertThrows(PayerCallException.class,
                () -> client.callHook(record, "order-sign-crd", REQUEST));

        assertEquals(OptionalInt.of(401), failure.statusCode());
        assertEquals(1, hookRequests.get(), "hook requests");
        assertEquals(0, tokenRequests.get(), "token requests");
    }

    private ConnectionRecord record(AuthType authType) throws Exception {
        switch (authType) {
            case NONE -> { }
            case API_KEY -> secrets.put(TestRecords.CREDENTIAL_REF, "synthetic-api-key");
            case CDS_HOOKS_JWT -> secrets.put(TestRecords.CREDENTIAL_REF, TestKeys.privateKeyPem(TestKeys.ec("secp384r1")));
            default -> throw new IllegalArgumentException("not a non-OAuth type under test: " + authType);
        }
        return TestRecords.forAuth(authType, payer).payerId("PAYER-" + authType).tokenEndpoint(payer.url("/token"))
                .build();
    }

    private CredentialProvider credentials() {
        return new CredentialProvider() {
            @Override public Optional<String> resolve(String ref) { return Optional.ofNullable(secrets.get(ref)); }
            @Override public void put(String ref, String value) { secrets.put(ref, value); }
            @Override public void remove(String ref) { secrets.remove(ref); }
        };
    }
}
