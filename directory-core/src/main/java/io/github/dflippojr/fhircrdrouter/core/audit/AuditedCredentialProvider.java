package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Opt-in audited view of a {@link CredentialProvider}. Events hold an opaque reference only:
 * never a secret, ciphertext, hash of a secret, or exception text.
 *
 * <ul>
 *   <li>{@code credential.put}: ATTEMPTED then SUCCEEDED/FAILED. The prior secret is never
 *       resolved, so create versus replace is not distinguished.</li>
 *   <li>{@code credential.remove}: same protocol. The {@link CredentialProvider} contract makes a
 *       missing target a silent no-op, so a SUCCEEDED remove does not prove a secret existed.</li>
 *   <li>One event per resolve, recorded after the lookup: {@code credential.resolve.found},
 *       {@code credential.resolve.not_found} or {@code credential.resolve.failed.<reason>} with
 *       reason {@code io_error} or {@code provider_error}. If that event cannot be recorded the
 *       secret is discarded and {@link AuditPersistenceException} is thrown. This records
 *       resolution, not downstream use of the value.</li>
 * </ul>
 * If the delegate is a {@link ContextualCredentialProvider} the context is passed down so side
 * effects such as key creation are attributed to the same caller.
 */
public final class AuditedCredentialProvider implements CredentialProvider {
    public static final String TARGET_KIND = "credential";

    private final CredentialProvider delegate;
    private final AuditSink sink;

    public AuditedCredentialProvider(CredentialProvider delegate, AuditSink sink) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.sink = Objects.requireNonNull(sink, "sink");
    }

    @Override
    public Optional<String> resolve(String credentialRef) {
        return resolve(AuditContext.unknown(), credentialRef);
    }

    @Override
    public void put(String credentialRef, String secretValue) {
        put(AuditContext.unknown(), credentialRef, secretValue);
    }

    @Override
    public void remove(String credentialRef) {
        remove(AuditContext.unknown(), credentialRef);
    }

    public Optional<String> resolve(AuditContext context, String credentialRef) {
        Objects.requireNonNull(context, "context");
        String target = AuditTargets.opaque(credentialRef);
        Optional<String> result;
        try {
            result = delegate instanceof ContextualCredentialProvider c
                    ? c.resolve(context, credentialRef) : delegate.resolve(credentialRef);
        } catch (AuditPersistenceException e) {
            throw e;
        } catch (RuntimeException failure) {
            String reason = failure instanceof UncheckedIOException ? "io_error" : "provider_error";
            try {
                sink.record(context, "credential.resolve.failed." + reason, TARGET_KIND, target, null,
                        AuditEvent.Outcome.FAILED, List.of());
            } catch (AuditPersistenceException auditFailure) {
                failure.addSuppressed(auditFailure);
            }
            throw failure;
        }
        sink.record(context, result.isPresent() ? "credential.resolve.found" : "credential.resolve.not_found",
                TARGET_KIND, target, null, AuditEvent.Outcome.SUCCEEDED, List.of());
        return result;
    }

    public void put(AuditContext context, String credentialRef, String secretValue) {
        Objects.requireNonNull(context, "context");
        mutate(context, "credential.put", credentialRef, () -> {
            if (delegate instanceof ContextualCredentialProvider c) c.put(context, credentialRef, secretValue);
            else delegate.put(credentialRef, secretValue);
        });
    }

    public void remove(AuditContext context, String credentialRef) {
        Objects.requireNonNull(context, "context");
        mutate(context, "credential.remove", credentialRef, () -> {
            if (delegate instanceof ContextualCredentialProvider c) c.remove(context, credentialRef);
            else delegate.remove(credentialRef);
        });
    }

    private void mutate(AuditContext context, String action, String ref, Runnable mutation) {
        String target = AuditTargets.opaque(ref);
        sink.record(context, action, TARGET_KIND, target, null, AuditEvent.Outcome.ATTEMPTED, List.of());
        try {
            mutation.run();
        } catch (AuditPersistenceException e) {
            throw e;
        } catch (RuntimeException | Error failure) {
            try {
                sink.record(context, action, TARGET_KIND, target, null, AuditEvent.Outcome.FAILED, List.of());
            } catch (AuditPersistenceException auditFailure) {
                failure.addSuppressed(auditFailure);
            }
            throw failure;
        }
        sink.record(context, action, TARGET_KIND, target, null, AuditEvent.Outcome.SUCCEEDED, List.of());
    }
}
