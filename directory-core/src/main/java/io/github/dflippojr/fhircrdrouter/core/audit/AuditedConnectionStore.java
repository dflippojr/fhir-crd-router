package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.ConnectionStore;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.InvalidConnectionRecordException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Function;

/**
 * Opt-in audited view of a {@link ConnectionStore}. Mutations use the #39 protocol: ATTEMPTED is
 * forced before the delegate runs, then SUCCEEDED or FAILED. If the attempt cannot be recorded the
 * delegate is never called ({@code ATTEMPT_NOT_RECORDED}); if the completion cannot be recorded the
 * mutation has already happened ({@code COMPLETED_ACTION_AUDIT_FAILED}) and must not be retried.
 *
 * <p>Actions: {@code connection.create}, {@code connection.update}, {@code connection.no_change}
 * (identical save, ignoring createdAt/updatedAt; the delegate is still called, as before),
 * {@code connection.delete} and {@code connection.delete_missing}. Events carry changed field
 * names only, never values. Reads pass straight through and are not audited. The plain
 * {@code save}/{@code delete} use {@link AuditContext#unknown()}. Classification is serialized
 * with the write, so it is exact for writers that go through this instance (one store instance
 * should own the file). The delegate throwing {@link AuditPersistenceException} is a failed mutation
 * like any other: FAILED is recorded and the exception propagates.
 *
 * <p>When the delegate holds an entry for the key that it cannot read and says so with
 * {@link InvalidConnectionRecordException} (#231), a save over it is {@code connection.update} with
 * every field the save sets, since the old values are unknown, and a delete is {@code connection.delete}.
 */
public final class AuditedConnectionStore implements ConnectionStore {
    public static final String TARGET_KIND = "connection";

    private record Field(String name, Function<ConnectionRecord, Object> getter) { }

    /** Everything except the key (payerId/environment) and the unreliable createdAt/updatedAt clocks. */
    private static final List<Field> FIELDS = List.of(
            new Field("displayName", ConnectionRecord::displayName),
            new Field("baseUrl", ConnectionRecord::baseUrl),
            new Field("authType", ConnectionRecord::authType),
            new Field("tokenEndpoint", ConnectionRecord::tokenEndpoint),
            new Field("clientId", ConnectionRecord::clientId),
            new Field("keyId", ConnectionRecord::keyId),
            new Field("jwksUrl", ConnectionRecord::jwksUrl),
            new Field("tenant", ConnectionRecord::tenant),
            new Field("scopes", ConnectionRecord::scopes),
            new Field("credentialRef", ConnectionRecord::credentialRef),
            new Field("mtlsCredentialRef", ConnectionRecord::mtlsCredentialRef),
            new Field("igVersion", ConnectionRecord::igVersion),
            new Field("status", ConnectionRecord::status),
            new Field("lastVerifiedAt", ConnectionRecord::lastVerifiedAt),
            new Field("contactInfo", ConnectionRecord::contactInfo));

    private final ConnectionStore delegate;
    private final AuditedMutation mutation;
    private final ReentrantLock writeLock = new ReentrantLock();

    public AuditedConnectionStore(ConnectionStore delegate, AuditSink sink) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.mutation = new AuditedMutation(sink, TARGET_KIND, AuditedMutation.DelegateAuditFailure.RECORD_FAILED);
    }

    @Override
    public List<ConnectionRecord> findByPayerId(String payerId) {
        return delegate.findByPayerId(payerId);
    }

    @Override
    public Optional<ConnectionRecord> findByPayerIdAndEnvironment(String payerId, Environment environment) {
        return delegate.findByPayerIdAndEnvironment(payerId, environment);
    }

    @Override
    public List<ConnectionRecord> findAll() {
        return delegate.findAll();
    }

    @Override
    public void save(ConnectionRecord record) {
        save(AuditContext.unknown(), record);
    }

    @Override
    public void delete(String payerId, Environment environment) {
        delete(AuditContext.unknown(), payerId, environment);
    }

    public void save(AuditContext context, ConnectionRecord record) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(record, "record");
        writeLock.lock();
        try {
            Optional<ConnectionRecord> before;
            try {
                before = delegate.findByPayerIdAndEnvironment(record.payerId(), record.environment());
            } catch (InvalidConnectionRecordException e) {
                // The key has a stored entry this version cannot read (#231). Saving over it is how it is
                // repaired, so record an update that names every field the save sets.
                mutation.run(context, "connection.update", record.payerId(), record.environment(),
                        presentFields(record), () -> delegate.save(record));
                return;
            }
            String action;
            List<String> fields;
            if (before.isEmpty()) {
                action = "connection.create";
                fields = presentFields(record);
            } else {
                fields = changedFields(before.get(), record);
                action = fields.isEmpty() ? "connection.no_change" : "connection.update";
            }
            mutation.run(context, action, record.payerId(), record.environment(), fields, () -> delegate.save(record));
        } finally {
            writeLock.unlock();
        }
    }

    public void delete(AuditContext context, String payerId, Environment environment) {
        Objects.requireNonNull(context, "context");
        Objects.requireNonNull(payerId, "payerId");
        Objects.requireNonNull(environment, "environment");
        writeLock.lock();
        try {
            boolean exists;
            try {
                exists = delegate.findByPayerIdAndEnvironment(payerId, environment).isPresent();
            } catch (InvalidConnectionRecordException e) {
                exists = true; // an entry this version cannot read is still there to delete (#231)
            }
            mutation.run(context, exists ? "connection.delete" : "connection.delete_missing", payerId,
                    environment, List.of(), () -> delegate.delete(payerId, environment));
        } finally {
            writeLock.unlock();
        }
    }

    private static List<String> presentFields(ConnectionRecord record) {
        List<String> names = new ArrayList<>();
        for (Field field : FIELDS) {
            Object value = field.getter().apply(record);
            if (value != null && !(value instanceof List<?> list && list.isEmpty())) names.add(field.name());
        }
        return names;
    }

    private static List<String> changedFields(ConnectionRecord before, ConnectionRecord after) {
        List<String> names = new ArrayList<>();
        for (Field field : FIELDS) {
            if (!Objects.equals(field.getter().apply(before), field.getter().apply(after))) names.add(field.name());
        }
        return names;
    }
}
