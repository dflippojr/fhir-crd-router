package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
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
    void newFieldsSurviveYamlRoundTrip(@TempDir Path tempDir) {
        Path file = tempDir.resolve("connections.yaml");
        new FileBasedConnectionStore(file).save(base(AuthType.CDS_HOOKS_JWT)
                .clientId("https://ehr.test/cds-client")
                .keyId("key-2026-09")
                .jwksUrl("https://ehr.test/.well-known/jwks.json")
                .tenant("clinic-7")
                .credentialRef("signing-key")
                .mtlsCredentialRef("client-cert")
                .build());

        ConnectionRecord reloaded = new FileBasedConnectionStore(file).findAll().get(0);

        assertEquals(AuthType.CDS_HOOKS_JWT, reloaded.authType());
        assertEquals("key-2026-09", reloaded.keyId());
        assertEquals("https://ehr.test/.well-known/jwks.json", reloaded.jwksUrl());
        assertEquals("clinic-7", reloaded.tenant());
        assertEquals("client-cert", reloaded.mtlsCredentialRef());
    }

    private static ConnectionRecord.Builder base(AuthType authType) {
        return ConnectionRecord.builder()
                .payerId("PAYER-AUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("https://payer.test/cds")
                .authType(authType);
    }
}
