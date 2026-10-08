package io.github.dflippojr.fhircrdrouter.core.audit;

import java.time.Instant;
import java.util.UUID;

/** Null filters mean any; UTC range is inclusive from, exclusive to. File order, oldest first. */
public record AuditQuery(Instant from, Instant to, AuditContext.ActorKind actorKind, String actorId,
                         String targetKind, String targetId, String action, UUID correlationId, int limit) {
    public AuditQuery {
        if (limit < 1 || limit > 10_000) throw new IllegalArgumentException("Limit must be 1-10000");
        if (from != null && to != null && !from.isBefore(to)) {
            throw new IllegalArgumentException("Invalid time range");
        }
    }

    public static AuditQuery all(int limit) {
        return new AuditQuery(null, null, null, null, null, null, null, null, limit);
    }

    boolean matches(AuditEvent event) {
        return (from == null || !event.occurredAt().isBefore(from))
                && (to == null || event.occurredAt().isBefore(to))
                && (actorKind == null || actorKind == event.context().actorKind())
                && (actorId == null || actorId.equals(event.context().actorId()))
                && (targetKind == null || targetKind.equals(event.targetKind()))
                && (targetId == null || targetId.equals(event.targetId()))
                && (action == null || action.equals(event.action()))
                && (correlationId == null || correlationId.equals(event.context().correlationId()));
    }
}
