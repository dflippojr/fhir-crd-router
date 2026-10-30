package io.github.dflippojr.fhircrdrouter.client.internal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

/** The redaction from #195, without a payer: what is replaced, and what is left alone. */
class EchoedCredentialsTest {

    @Test
    void replacesEveryOccurrenceOfEachCredential() {
        assertEquals("[REDACTED] then [REDACTED] and [REDACTED]",
                EchoedCredentials.redact("key-1 then key-1 and secret", "key-1", "secret"));
    }

    @Test
    void absentOrEmptyCredentialLeavesBodyAlone() {
        // String.replace("", ...) would put the marker between every character.
        assertEquals("body", EchoedCredentials.redact("body", null, ""));
        assertEquals("body", EchoedCredentials.redact("body"));
    }

    @Test
    void nullBodyStaysNull() {
        assertNull(EchoedCredentials.redact(null, "key"));
    }

    @ParameterizedTest
    @CsvSource({"Bearer abc.def, abc.def", "Basic dXNlcjpwYXNz, dXNlcjpwYXNz", "bare-token, bare-token",
            "' leading', ' leading'"})
    void credentialFollowsTheScheme(String header, String credential) {
        assertEquals(credential, EchoedCredentials.fromAuthorization(header));
    }

    @Test
    void noHeaderMeansNoCredential() {
        assertNull(EchoedCredentials.fromAuthorization(null));
    }
}
