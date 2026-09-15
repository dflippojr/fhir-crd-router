package io.github.dflippojr.fhircrdrouter.core;

import java.util.Optional;

/**
 * Adapter contract for resolving the secret material behind a
 * {@link ConnectionRecord#credentialRef()}. A {@code ConnectionRecord} never
 * holds a raw secret itself, only an opaque reference key into whichever
 * provider is configured (encrypted-local by default; Vault / AWS Secrets
 * Manager / Azure Key Vault as alternative adapters).
 */
public interface CredentialProvider {

    /**
     * Resolves the secret material for the given reference.
     *
     * @param credentialRef opaque key, as stored on a {@link ConnectionRecord}
     * @return the secret value (e.g. client secret, API key, or PEM-encoded
     *     client certificate material), or empty if no such reference exists
     */
    Optional<String> resolve(String credentialRef);

    /**
     * Stores or replaces the secret material for a reference, creating it if
     * it doesn't already exist.
     */
    void put(String credentialRef, String secretValue);

    /** Removes a stored secret. No-op if it doesn't exist. */
    void remove(String credentialRef);
}
