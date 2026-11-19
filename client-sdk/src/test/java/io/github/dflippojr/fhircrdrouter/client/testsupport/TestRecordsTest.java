package io.github.dflippojr.fhircrdrouter.client.testsupport;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class TestRecordsTest {

    private static final String ORIGIN = "http://127.0.0.1:9";

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void everyAuthTypeBuildsWithTheFieldsItRequires(AuthType authType) {
        ConnectionRecord record = TestRecords.forAuth(authType, ORIGIN).build();

        assertEquals(authType, record.authType());
        assertEquals(ORIGIN, record.baseUrl());
        assertEquals(TestRecords.PAYER_ID, record.payerId());
        assertEquals(Environment.SANDBOX, record.environment());
        assertEquals(authType.usesOAuth2Token() ? ORIGIN + TestRecords.TOKEN_PATH : null, record.tokenEndpoint());
        assertEquals(authType.usesOAuth2Token() || authType.signsJwt() ? TestRecords.CLIENT_ID : null,
                record.clientId());
        assertEquals(authType.signsJwt() ? TestRecords.KEY_ID : null, record.keyId());
        assertEquals(authType == AuthType.NONE ? null : TestRecords.CREDENTIAL_REF, record.credentialRef());
        assertNull(record.mtlsCredentialRef());
        assertEquals(List.of(), record.scopes());
    }

    @Test
    void theNamedBuildersPointAtThePayersOrigin() {
        Map<AuthType, Function<LoopbackPayer, ConnectionRecord.Builder>> named = Map.of(
                AuthType.NONE, TestRecords::none,
                AuthType.API_KEY, TestRecords::apiKey,
                AuthType.OAUTH2_CLIENT_CREDENTIALS, TestRecords::oauth2,
                AuthType.OAUTH2_PRIVATE_KEY_JWT, TestRecords::privateKeyJwt,
                AuthType.CDS_HOOKS_JWT, TestRecords::cdsHooksJwt);
        assertEquals(AuthType.values().length, named.size(), "one named builder per auth type");

        try (LoopbackPayer payer = new LoopbackPayer()) {
            named.forEach((authType, builder) -> {
                ConnectionRecord record = builder.apply(payer).build();
                ConnectionRecord expected = TestRecords.forAuth(authType, payer.origin()).build();
                assertEquals(authType, record.authType());
                assertEquals(payer.origin(), record.baseUrl());
                assertEquals(expected.tokenEndpoint(), record.tokenEndpoint());
                assertEquals(expected.clientId(), record.clientId());
                assertEquals(expected.keyId(), record.keyId());
                assertEquals(expected.credentialRef(), record.credentialRef());
            });
        }
    }

    @Test
    void aTestChangesOnlyTheFieldsItIsAbout() {
        ConnectionRecord record = TestRecords.forAuth(AuthType.OAUTH2_CLIENT_CREDENTIALS, ORIGIN)
                .scopes(List.of("crd")).clientId("other-client").build();

        assertEquals(List.of("crd"), record.scopes());
        assertEquals("other-client", record.clientId());
        assertEquals(ORIGIN + TestRecords.TOKEN_PATH, record.tokenEndpoint());
    }
}
