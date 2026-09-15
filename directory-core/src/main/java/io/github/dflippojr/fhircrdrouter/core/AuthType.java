package io.github.dflippojr.fhircrdrouter.core;

/**
 * How requests to a payer's CDS Hooks endpoint are authenticated at the HTTP
 * layer. Mutual TLS is a separate, combinable transport setting — see
 * {@link ConnectionRecord#mtlsCredentialRef()}.
 */
public enum AuthType {

    /** No {@code Authorization} header. */
    NONE,

    /** {@code Authorization: Bearer <secret>}, where the secret is resolved from {@code credentialRef}. */
    API_KEY,

    /**
     * OAuth2 client credentials with a shared secret ({@code client_secret_basic}).
     * Requires {@code tokenEndpoint} and {@code clientId}; {@code credentialRef} resolves to the client secret.
     */
    OAUTH2_CLIENT_CREDENTIALS,

    /**
     * OAuth2 client credentials authenticated with a signed JWT assertion
     * ({@code private_key_jwt}, as in SMART Backend Services). Requires
     * {@code tokenEndpoint}, {@code clientId} and {@code keyId};
     * {@code credentialRef} resolves to a PKCS#8 PEM private key.
     */
    OAUTH2_PRIVATE_KEY_JWT,

    /**
     * The CDS Hooks 2.0 client authentication JWT: a short-lived JWT signed
     * per request and sent as {@code Authorization: Bearer}. Requires
     * {@code clientId} (the {@code iss} claim) and {@code keyId};
     * {@code credentialRef} resolves to a PKCS#8 PEM private key.
     */
    CDS_HOOKS_JWT
}
