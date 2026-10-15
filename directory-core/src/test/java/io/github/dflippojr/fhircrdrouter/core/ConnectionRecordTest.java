package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectionRecordTest {

    @Test
    void jwtAuthTypesRequireClientIdAndKeyId() {
        assertThrows(IllegalArgumentException.class, () -> base(AuthType.CDS_HOOKS_JWT).keyId("k").build());
        IllegalArgumentException missingKey = assertThrows(IllegalArgumentException.class,
                () -> base(AuthType.CDS_HOOKS_JWT).clientId("iss").build());
        assertTrue(missingKey.getMessage().contains("keyId"));
        assertDoesNotThrow(() -> base(AuthType.CDS_HOOKS_JWT).clientId("iss").keyId("k").build());

        assertThrows(IllegalArgumentException.class, () -> base(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                .clientId("c").keyId("k").build(), "tokenEndpoint required");
        assertDoesNotThrow(() -> base(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                .clientId("c").keyId("k").tokenEndpoint("https://payer.test/token").build());
    }

    @Test
    void mutualTlsCombinesWithAnyAuthType() {
        assertDoesNotThrow(() -> base(AuthType.NONE).mtlsCredentialRef("cert").build());
        assertDoesNotThrow(() -> base(AuthType.OAUTH2_CLIENT_CREDENTIALS).mtlsCredentialRef("cert")
                .tokenEndpoint("https://payer.test/token").clientId("c").build());
    }

    @Test
    void withLastVerifiedAtChangesOnlyThatField() {
        ConnectionRecord original = base(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .displayName("Synthetic").tokenEndpoint("https://payer.test/token").clientId("c")
                .scopes(List.of("system/*.read")).credentialRef("ref").mtlsCredentialRef("cert")
                .igVersion("2.1.0").status(ConnectionStatus.INACTIVE).contactInfo("ops@payer.test")
                .createdAt(Instant.EPOCH).updatedAt(Instant.EPOCH.plusSeconds(60)).build();
        Instant verifiedAt = Instant.parse("2026-10-13T12:00:00Z");

        ConnectionRecord verified = original.withLastVerifiedAt(verifiedAt);

        assertEquals(verifiedAt, verified.lastVerifiedAt());
        assertEquals(Instant.EPOCH.plusSeconds(60), verified.updatedAt());
        assertNull(original.lastVerifiedAt());
        // Every other component is equal: clearing the field again restores the original.
        assertEquals(original, verified.withLastVerifiedAt(null));
    }

    private static ConnectionRecord.Builder base(AuthType authType) {
        return ConnectionRecord.builder()
                .payerId("PAYER-AUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("https://payer.test/cds")
                .authType(authType);
    }
}
