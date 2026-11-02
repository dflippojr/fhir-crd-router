package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.EndpointUrlException;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The URL rule from #156, checked without a network: loopback is decided from the literal host alone. */
class EndpointUrlsTest {

    private static final ConnectionRecord RECORD = ConnectionRecord.builder().payerId("P")
            .environment(Environment.SANDBOX).baseUrl("https://payer.example").authType(AuthType.NONE).build();

    /**
     * The URL fields {@link EndpointUrls#requireUsable} checks for each auth type, in check order. baseUrl is
     * always first. Every AuthType needs a row: {@link #everyAuthTypeIsListed} fails until a new constant is decided.
     */
    private static final Map<AuthType, List<String>> CHECKED = Map.of(
            AuthType.NONE, List.of("baseUrl"),
            AuthType.API_KEY, List.of("baseUrl"),
            AuthType.OAUTH2_CLIENT_CREDENTIALS, List.of("baseUrl", "tokenEndpoint"),
            AuthType.OAUTH2_PRIVATE_KEY_JWT, List.of("baseUrl", "tokenEndpoint", "jwksUrl"),
            AuthType.CDS_HOOKS_JWT, List.of("baseUrl", "jwksUrl"));

    @Test
    void everyAuthTypeIsListed() {
        assertEquals(EnumSet.allOf(AuthType.class), CHECKED.keySet());
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void checksExactlyTheUrlsItsAuthTypeUses(AuthType authType) {
        for (String field : List.of("baseUrl", "tokenEndpoint", "jwksUrl")) {
            ConnectionRecord record = recordWithRemoteHttp(authType, field);
            if (CHECKED.get(authType).contains(field)) {
                assertEquals(field, assertThrows(EndpointUrlException.class,
                        () -> EndpointUrls.requireUsable(record)).field());
            } else {
                assertDoesNotThrow(() -> EndpointUrls.requireUsable(record), field);
            }
        }
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void refusesTheEarliestCheckedUrlFirst(AuthType authType) {
        // baseUrl is https; tokenEndpoint and jwksUrl are both remote http, so the first refusal
        // must name the first of them that this auth type checks.
        ConnectionRecord record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl("https://payer.example/r4").authType(authType).clientId("c").keyId("k")
                .tokenEndpoint("http://auth.example/token").jwksUrl("http://ehr.example/jwks.json").build();
        List<String> checked = CHECKED.get(authType).stream().filter(f -> !f.equals("baseUrl")).toList();

        if (checked.isEmpty()) {
            assertDoesNotThrow(() -> EndpointUrls.requireUsable(record));
        } else {
            assertEquals(checked.get(0), assertThrows(EndpointUrlException.class,
                    () -> EndpointUrls.requireUsable(record)).field());
        }
    }

    /** A record of {@code authType} whose {@code field} is {@code http://remote.example}; every other URL is https. */
    private static ConnectionRecord recordWithRemoteHttp(AuthType authType, String field) {
        String baseUrl = field.equals("baseUrl") ? "http://remote.example/r4" : "https://payer.example/r4";
        String tokenEndpoint = field.equals("tokenEndpoint") ? "http://remote.example/token" : "https://auth.example/token";
        String jwksUrl = field.equals("jwksUrl") ? "http://remote.example/jwks.json" : "https://ehr.example/jwks.json";
        return ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(baseUrl).authType(authType).clientId("c").keyId("k")
                .tokenEndpoint(tokenEndpoint).jwksUrl(jwksUrl).build();
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "LocalHost", "127.0.0.1", "127.255.255.255", "127.0.0.0", "[::1]",
            "[0:0:0:0:0:0:0:1]", "[::ffff:127.0.0.1]"})
    void loopbackHosts(String host) {
        assertTrue(EndpointUrls.isLoopback(host), host);
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost.evil.example", "127.0.0.1.evil.example", "evil-localhost", "localhost.",
            "127.0.0.256", "127.0.0", "127.1", "127.000.000.001", "128.0.0.1", "0.0.0.0", "[::]", "[::2]",
            "[fe80::1]", "[::ffff:10.0.0.1]", "[not-an-address]", "[::1", "example.org"})
    void notLoopbackHosts(String host) {
        assertFalse(EndpointUrls.isLoopback(host), host);
    }

    @ParameterizedTest
    @ValueSource(strings = {"https://payer.example/r4", "HTTPS://payer.example", "https://payer.example:8443/r4/",
            "http://localhost:8089", "http://127.0.0.1:18090/r4", "Http://[::1]:80/x"})
    void acceptedUrls(String url) {
        assertEquals(URI.create(url), EndpointUrls.require(RECORD, "baseUrl", url));
    }

    @ParameterizedTest
    @CsvSource(delimiter = '|', value = {
            "http://payer.example/r4|must use https: http is allowed only to a loopback host",
            "https://payer example/r4|is not a valid URI",
            "payer.example/r4|is not an absolute URI",
            "ftp://payer.example/r4|must be an https URL",
            "user:pw@payer.example|must be an https URL",
            "https:///r4|has no host",
            "https:payer.example|has no host",
            "' '|is not set",
    })
    void refusedUrls(String url, String problem) {
        EndpointUrlException e = assertThrows(EndpointUrlException.class,
                () -> EndpointUrls.require(RECORD, "baseUrl", url));

        assertEquals(problem, e.problem());
        assertEquals("baseUrl for payerId=P " + problem, e.getMessage());
        assertFalse(e.getMessage().contains("pw"), e.getMessage());
    }

    @ParameterizedTest
    @NullSource
    void missingUrlIsRefused(String url) {
        assertEquals("is not set",
                assertThrows(EndpointUrlException.class, () -> EndpointUrls.require(RECORD, "jwksUrl", url)).problem());
    }
}
