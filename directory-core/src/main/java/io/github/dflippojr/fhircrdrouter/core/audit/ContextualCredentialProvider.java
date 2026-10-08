package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import java.util.Optional;

/**
 * Optional extension for providers that can attribute their own side effects (for example local
 * key creation) to the initiating caller. The plain {@link CredentialProvider} methods behave as
 * the context versions called with {@link AuditContext#unknown()}.
 */
public interface ContextualCredentialProvider extends CredentialProvider {
    Optional<String> resolve(AuditContext context, String credentialRef);

    void put(AuditContext context, String credentialRef, String secretValue);

    void remove(AuditContext context, String credentialRef);
}
