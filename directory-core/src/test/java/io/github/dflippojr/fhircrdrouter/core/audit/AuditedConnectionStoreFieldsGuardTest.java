package io.github.dflippojr.fhircrdrouter.core.audit;

import static org.junit.jupiter.api.Assertions.assertTrue;

import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStatus;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.FileBasedConnectionStore;
import java.lang.reflect.RecordComponent;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Guard for the hand-written {@code AuditedConnectionStore.FIELDS} list (issue #173): every
 * {@link ConnectionRecord} component except the key and the clocks must be named in the audit event
 * when it changes. It goes through the public {@code save} path, so {@code FIELDS} stays private.
 */
class AuditedConnectionStoreFieldsGuardTest {

    /** The key (payerId, environment) and the unreliable clocks, as documented on {@code FIELDS}. */
    private static final Set<String> NOT_AUDITED = Set.of("payerId", "environment", "createdAt", "updatedAt");

    @Test
    void everyComponentOutsideTheKeyAndClocksIsAuditedWhenItChanges(@TempDir Path dir)
            throws ReflectiveOperationException {
        ConnectionRecord base = baseRecord();
        for (RecordComponent component : ConnectionRecord.class.getRecordComponents()) {
            String name = component.getName();
            if (NOT_AUDITED.contains(name)) continue;

            List<String> changedFields = new ArrayList<>();
            AuditSink sink = (context, action, targetKind, targetId, environment, outcome, fields) -> {
                if (outcome == AuditEvent.Outcome.SUCCEEDED) changedFields.addAll(fields);
                return null;
            };
            var store = new AuditedConnectionStore(new FileBasedConnectionStore(dir.resolve(name + ".yaml")), sink);
            store.save(AuditContext.unknown(), base);
            changedFields.clear();

            Object current = component.getAccessor().invoke(base);
            store.save(AuditContext.unknown(),
                    withComponent(base, name, differentValue(name, component.getType(), current)));

            assertTrue(changedFields.contains(name),
                    () -> "AuditedConnectionStore.FIELDS does not audit ConnectionRecord component '" + name
                            + "': changing it audited as " + changedFields);
        }
    }

    /** Every component set, so each change is visible and the auth-type requirements are met. */
    private static ConnectionRecord baseRecord() {
        return ConnectionRecord.builder().payerId("synthetic-payer").environment(Environment.SANDBOX)
                .displayName("base-name").baseUrl("https://base.example.invalid/fhir")
                .authType(AuthType.OAUTH2_PRIVATE_KEY_JWT).tokenEndpoint("https://base.example.invalid/token")
                .clientId("base-client").keyId("base-key").jwksUrl("https://base.example.invalid/jwks")
                .tenant("base-tenant").scopes(List.of("base-scope")).credentialRef("base-ref")
                .mtlsCredentialRef("base-mtls-ref").igVersion("base-ig").status(ConnectionStatus.ACTIVE)
                .lastVerifiedAt(Instant.parse("2026-10-01T00:00:00Z")).contactInfo("base-contact")
                .build();
    }

    /** A copy of {@code record} with one component replaced, built through the canonical constructor. */
    private static ConnectionRecord withComponent(ConnectionRecord record, String name, Object value)
            throws ReflectiveOperationException {
        RecordComponent[] components = ConnectionRecord.class.getRecordComponents();
        Class<?>[] types = new Class<?>[components.length];
        Object[] args = new Object[components.length];
        for (int i = 0; i < components.length; i++) {
            types[i] = components[i].getType();
            args[i] = components[i].getName().equals(name) ? value : components[i].getAccessor().invoke(record);
        }
        return ConnectionRecord.class.getDeclaredConstructor(types).newInstance(args);
    }

    /** A value of {@code type} that differs from {@code current}. Extend it when a component adds a new type. */
    private static Object differentValue(String name, Class<?> type, Object current) {
        if (type == String.class) return current + "-changed";
        if (type == List.class) return List.of("changed-scope");
        if (type == Instant.class) return Instant.parse("2030-01-01T00:00:00Z");
        if (type.isEnum()) {
            Object[] constants = type.getEnumConstants();
            return constants[(((Enum<?>) current).ordinal() + 1) % constants.length];
        }
        throw new IllegalStateException("no test value for ConnectionRecord component '" + name
                + "' of type " + type.getName());
    }
}
