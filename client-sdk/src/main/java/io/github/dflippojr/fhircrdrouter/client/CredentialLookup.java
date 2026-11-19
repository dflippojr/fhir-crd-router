package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.internal.BearerTokens;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditPersistenceException;

import java.util.Optional;

/**
 * Reads the credentials {@link CdsHooksClient} uses through its {@link CredentialProvider}, and the exceptions
 * that say a credential could not be used. A provider's own message is never copied into them.
 */
final class CredentialLookup {
    private final CredentialProvider credentialProvider;

    CredentialLookup(CredentialProvider credentialProvider) {
        this.credentialProvider = credentialProvider;
    }

    /**
     * A credential that could not be used. {@code phase} is the call the credential belongs to, or
     * null when it belongs to the request being sent.
     */
    abstract static class CredentialFailure extends RouterException {
        private final transient PayerCallPhase phase;

        CredentialFailure(String message, PayerCallPhase phase) {
            super(message);
            this.phase = phase;
        }

        CredentialFailure(String message, PayerCallPhase phase, RuntimeException cause) {
            super(message, cause);
            this.phase = phase;
        }

        /** The phase a verify report names: the credential's own call, or discovery when it is null. */
        PayerCallPhase phaseOrDiscovery() {
            return phase == null ? PayerCallPhase.DISCOVERY : phase;
        }
    }

    /** A credential reference that is unset or does not resolve; keeps the existing message. */
    static final class MissingCredentialException extends CredentialFailure {
        MissingCredentialException(String message, PayerCallPhase phase) {
            super(message, phase);
        }
    }

    /**
     * The credential provider threw while resolving a reference, for example a key mismatch or an
     * unreadable secrets file. The provider's exception is kept as the cause; its message is not
     * copied, since it may describe secret material.
     */
    static final class CredentialReadException extends CredentialFailure {
        CredentialReadException(String message, PayerCallPhase phase, RuntimeException cause) {
            super(message, phase, cause);
        }
    }

    /** The stored key, which must be a b64token: anything else, e.g. a trailing newline, is not a legal header value. */
    String requireApiKey(ConnectionRecord record) {
        String key = requireSecret(record);
        if (!BearerTokens.isB64Token(key)) {
            // Never echo the key: it is the credential.
            throw new RouterException("Credential for ref=" + record.credentialRef() + " (payerId="
                    + record.payerId() + ") is not a usable bearer token");
        }
        return key;
    }

    String requireSecret(ConnectionRecord record) {
        // An OAuth2 secret authenticates the token exchange; any other secret, the request itself.
        PayerCallPhase phase = record.authType().usesOAuth2Token() ? PayerCallPhase.TOKEN : null;
        if (record.credentialRef() == null) {
            throw new MissingCredentialException("authType=" + record.authType()
                    + " but no credentialRef set for payerId=" + record.payerId(), phase);
        }
        return resolveCredential(record, record.credentialRef(), phase)
                .orElseThrow(() -> new MissingCredentialException(
                        "No credential found for ref=" + record.credentialRef() + " (payerId=" + record.payerId() + ")", phase));
    }

    /**
     * Resolves a reference, wrapping a provider failure in a {@link RouterException} that keeps the
     * original as its cause. An {@link AuditPersistenceException} is not wrapped: callers must see it.
     */
    Optional<String> resolveCredential(ConnectionRecord record, String ref, PayerCallPhase phase) {
        try {
            return credentialProvider.resolve(ref);
        } catch (AuditPersistenceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new CredentialReadException("Failed to read credential for ref=" + ref
                    + " (payerId=" + record.payerId() + ")", phase, e);
        }
    }
}
