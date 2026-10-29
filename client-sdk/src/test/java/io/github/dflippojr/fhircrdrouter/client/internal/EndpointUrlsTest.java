package io.github.dflippojr.fhircrdrouter.client.internal;

import io.github.dflippojr.fhircrdrouter.client.EndpointUrlException;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** The URL rule from #156, checked without a network: loopback is decided from the literal host alone. */
class EndpointUrlsTest {

    private static final ConnectionRecord RECORD = ConnectionRecord.builder().payerId("P")
            .environment(Environment.SANDBOX).baseUrl("https://payer.example").authType(AuthType.NONE).build();

    @ParameterizedTest
    @ValueSource(strings = {"localhost", "LocalHost", "127.0.0.1", "127.255.255.255", "127.0.0.0", "[::1]",
            "[0:0:0:0:0:0:0:1]", "[::ffff:127.0.0.1]"})
    void loopbackHosts(String host) {
        assertTrue(EndpointUrls.isLoopback(host), host);
    }

    @ParameterizedTest
    @ValueSource(strings = {"localhost.evil.example", "127.0.0.1.evil.example", "evil-localhost", "localhost.",
            "127.0.0.256", "127.0.0", "127.1", "127.000.000.001", "128.0.0.1", "0.0.0.0", "[::]", "[::2]",
            "[fe80::1]", "[::ffff:10.0.0.1]", "[not-an-address]", "example.org"})
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
