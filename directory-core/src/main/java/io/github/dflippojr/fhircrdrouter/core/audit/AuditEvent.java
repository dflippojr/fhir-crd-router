package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Safe metadata only; callers must never put secrets or patient identifiers in IDs. */
public record AuditEvent(int schemaVersion, UUID eventId, Instant occurredAt, AuditContext context,
                         String action, String targetKind, String targetId, Environment environment,
                         Outcome outcome, List<String> changedFields) {
    public enum Outcome { ATTEMPTED, SUCCEEDED, FAILED }

    public AuditEvent {
        if (schemaVersion != 1) throw new IllegalArgumentException("Unsupported audit schema version");
        Objects.requireNonNull(eventId, "eventId");
        Objects.requireNonNull(occurredAt, "occurredAt");
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(outcome, "outcome");
        AuditContext.identifier(action);
        AuditContext.identifier(targetKind);
        AuditContext.identifier(targetId);
        changedFields = List.copyOf(changedFields);
        if (changedFields.size() > 64) throw new IllegalArgumentException("Too many changed fields");
        changedFields.forEach(AuditContext::identifier);
    }
}
