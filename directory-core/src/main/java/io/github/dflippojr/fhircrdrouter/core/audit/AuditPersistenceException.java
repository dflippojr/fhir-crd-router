package io.github.dflippojr.fhircrdrouter.core.audit;

import java.util.UUID;

/** Persistence may be partial even when append/force throws. Never retry a completed action. */
public final class AuditPersistenceException extends RuntimeException {
    public enum OperationState { ATTEMPT_NOT_RECORDED, COMPLETED_ACTION_AUDIT_FAILED }
    private final OperationState operationState;
    private final UUID eventId;
    private final UUID correlationId;

    AuditPersistenceException(AuditEvent event) {
        super("Audit persistence failed; durability is uncertain");
        operationState = event.outcome() == AuditEvent.Outcome.ATTEMPTED
                ? OperationState.ATTEMPT_NOT_RECORDED : OperationState.COMPLETED_ACTION_AUDIT_FAILED;
        eventId = event.eventId();
        correlationId = event.context().correlationId();
    }

    public OperationState operationState() { return operationState; }
    public UUID eventId() { return eventId; }
    public UUID correlationId() { return correlationId; }
}
