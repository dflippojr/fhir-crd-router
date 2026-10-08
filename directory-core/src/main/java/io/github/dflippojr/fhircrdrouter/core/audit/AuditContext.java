package io.github.dflippojr.fhircrdrouter.core.audit;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

/** Host-established attribution, never authentication or a clinical user identity. */
public record AuditContext(ActorKind actorKind, String actorId, String onBehalfOfActorId,
                           Source source, UUID correlationId) {
    public enum ActorKind { UNKNOWN, ANONYMOUS, CLIENT, SYSTEM, HOST_ADMINISTRATOR }
    public enum Source { API, CLI, JOB, AGENT, UNKNOWN }
    private static final Pattern IDENTIFIER = Pattern.compile("[A-Za-z0-9][A-Za-z0-9_.-]{0,127}");

    public AuditContext {
        Objects.requireNonNull(actorKind, "actorKind");
        Objects.requireNonNull(source, "source");
        Objects.requireNonNull(correlationId, "correlationId");
        identifier(actorId);
        if (onBehalfOfActorId != null) identifier(onBehalfOfActorId);
        if (actorKind == ActorKind.UNKNOWN && (!"unknown".equals(actorId)
                || onBehalfOfActorId != null || source != Source.UNKNOWN)) {
            throw new IllegalArgumentException("UNKNOWN attribution must be explicit");
        }
    }

    /** Legacy callers must not invent a person. One context per logical operation. */
    public static AuditContext unknown() {
        return new AuditContext(ActorKind.UNKNOWN, "unknown", null, Source.UNKNOWN, UUID.randomUUID());
    }

    static String identifier(String value) {
        if (value == null || !IDENTIFIER.matcher(value).matches()) {
            throw new IllegalArgumentException("Expected an opaque non-sensitive identifier (1-128 ASCII characters)");
        }
        return value;
    }
}
