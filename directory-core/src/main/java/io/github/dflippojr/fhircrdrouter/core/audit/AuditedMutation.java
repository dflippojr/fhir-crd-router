package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.util.List;
import java.util.Objects;

/**
 * The #39 mutation protocol shared by the audited wrappers: ATTEMPTED is recorded before the mutation
 * runs, so a failure to record it means the mutation never runs. Then SUCCEEDED is recorded, or FAILED
 * if the mutation throws, in which case the mutation's exception propagates and an
 * {@link AuditPersistenceException} from recording FAILED is added to it as suppressed.
 */
final class AuditedMutation {
    /** What to do when the mutation itself throws {@link AuditPersistenceException}. */
    enum DelegateAuditFailure {
        /** Record FAILED, as for any other failure. */
        RECORD_FAILED,
        /** Rethrow it with no FAILED event: the delegate's own audit trail already failed. */
        RETHROW
    }

    private final AuditSink sink;
    private final String targetKind;
    private final DelegateAuditFailure onDelegateAuditFailure;

    AuditedMutation(AuditSink sink, String targetKind, DelegateAuditFailure onDelegateAuditFailure) {
        this.sink = Objects.requireNonNull(sink, "sink");
        this.targetKind = Objects.requireNonNull(targetKind, "targetKind");
        this.onDelegateAuditFailure = Objects.requireNonNull(onDelegateAuditFailure, "onDelegateAuditFailure");
    }

    /** Records the event with {@link AuditTargets#opaque} of {@code targetId}, never the raw value. */
    void run(AuditContext context, String action, String targetId, Environment environment, List<String> fields,
             Runnable mutation) {
        String target = AuditTargets.opaque(targetId);
        sink.record(context, action, targetKind, target, environment, AuditEvent.Outcome.ATTEMPTED, fields);
        try {
            mutation.run();
        } catch (RuntimeException | Error failure) {
            boolean rethrow = onDelegateAuditFailure == DelegateAuditFailure.RETHROW;
            if (rethrow && failure instanceof AuditPersistenceException) throw failure;
            try {
                sink.record(context, action, targetKind, target, environment, AuditEvent.Outcome.FAILED, fields);
            } catch (AuditPersistenceException auditFailure) {
                failure.addSuppressed(auditFailure);
            }
            throw failure;
        }
        sink.record(context, action, targetKind, target, environment, AuditEvent.Outcome.SUCCEEDED, fields);
    }
}
