package io.github.dflippo.fhircrdrouter.core;

import java.util.List;
import java.util.Optional;

/**
 * Pluggable persistence for {@link ConnectionRecord}s. The default v1
 * implementation ({@link FileBasedConnectionStore}) is a flat YAML file;
 * swap in a DB-backed or otherwise pluggable implementation later without
 * touching {@link PayerRouter}.
 */
public interface ConnectionStore {

    List<ConnectionRecord> findByPayerId(String payerId);

    Optional<ConnectionRecord> findByPayerIdAndEnvironment(String payerId, Environment environment);

    List<ConnectionRecord> findAll();

    void save(ConnectionRecord record);

    void delete(String payerId, Environment environment);
}
