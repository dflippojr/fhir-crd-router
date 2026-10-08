package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.util.List;

/** Append-only destination for safe audit events; {@link JsonlAuditTrail} is the shipped implementation. */
public interface AuditSink {
    /** Throws {@link AuditPersistenceException} when the event cannot be recorded. */
    AuditEvent record(AuditContext context, String action, String targetKind, String targetId,
                      Environment environment, AuditEvent.Outcome outcome, List<String> changedFields);
}
