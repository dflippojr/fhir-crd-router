package io.github.dflippojr.fhircrdrouter.client.testsupport;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;

/**
 * {@link ConnectionRecord} builders for client tests, one per {@link AuthType}, each pointing at a
 * fake payer and carrying every field that auth type requires. They return the builder, so a test
 * changes only the fields it is about.
 */
public final class TestRecords {

    public static final String PAYER_ID = "PAYER-TEST";
    public static final String CLIENT_ID = "client";
    public static final String KEY_ID = "key-1";
    public static final String CREDENTIAL_REF = "credential";
    /** Where the OAuth2 records send token requests, under the payer's origin. */
    public static final String TOKEN_PATH = "/token";

    private TestRecords() {
    }

    /** A record for {@code authType} whose base URL is {@code payer}'s origin. */
    public static ConnectionRecord.Builder forAuth(AuthType authType, LoopbackPayer payer) {
        return forAuth(authType, payer.origin());
    }

    /**
     * A record for {@code authType} whose base URL is {@code origin}. OAuth2 records send token
     * requests to {@code origin + TOKEN_PATH}.
     *
     * <p>The switch has no {@code default}, so a new {@link AuthType} constant does not compile here
     * until it gets its required fields.
     */
    public static ConnectionRecord.Builder forAuth(AuthType authType, String origin) {
        ConnectionRecord.Builder builder = ConnectionRecord.builder()
                .payerId(PAYER_ID)
                .environment(Environment.SANDBOX)
                .baseUrl(origin)
                .authType(authType);
        return switch (authType) {
            case NONE -> builder;
            case API_KEY -> builder.credentialRef(CREDENTIAL_REF);
            case OAUTH2_CLIENT_CREDENTIALS -> builder.credentialRef(CREDENTIAL_REF)
                    .tokenEndpoint(origin + TOKEN_PATH).clientId(CLIENT_ID);
            case OAUTH2_PRIVATE_KEY_JWT -> builder.credentialRef(CREDENTIAL_REF)
                    .tokenEndpoint(origin + TOKEN_PATH).clientId(CLIENT_ID).keyId(KEY_ID);
            case CDS_HOOKS_JWT -> builder.credentialRef(CREDENTIAL_REF).clientId(CLIENT_ID).keyId(KEY_ID);
        };
    }

    /** No {@code Authorization} header. */
    public static ConnectionRecord.Builder none(LoopbackPayer payer) {
        return forAuth(AuthType.NONE, payer);
    }

    /** {@code Authorization: Bearer} with the secret {@link #CREDENTIAL_REF} resolves to. */
    public static ConnectionRecord.Builder apiKey(LoopbackPayer payer) {
        return forAuth(AuthType.API_KEY, payer);
    }

    /** OAuth2 client credentials with a client secret, tokens from {@code payer}'s {@link #TOKEN_PATH}. */
    public static ConnectionRecord.Builder oauth2(LoopbackPayer payer) {
        return forAuth(AuthType.OAUTH2_CLIENT_CREDENTIALS, payer);
    }

    /** OAuth2 client credentials with a signed client assertion, tokens from {@link #TOKEN_PATH}. */
    public static ConnectionRecord.Builder privateKeyJwt(LoopbackPayer payer) {
        return forAuth(AuthType.OAUTH2_PRIVATE_KEY_JWT, payer);
    }

    /** The CDS Hooks client JWT, signed per request with the key {@link #CREDENTIAL_REF} resolves to. */
    public static ConnectionRecord.Builder cdsHooksJwt(LoopbackPayer payer) {
        return forAuth(AuthType.CDS_HOOKS_JWT, payer);
    }
}
