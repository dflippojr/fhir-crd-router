package io.github.dflippo.fhircrdrouter.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Default v1 {@link ConnectionStore}: connection records as a flat YAML
 * list on disk. Whole-file read + rewrite on every mutation — fine for a
 * handful to a few hundred payer records; not meant to scale beyond that.
 */
public final class FileBasedConnectionStore implements ConnectionStore {

    private final Path path;
    private final ObjectMapper mapper;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public FileBasedConnectionStore(Path path) {
        this.path = path;
        this.mapper = new ObjectMapper(new YAMLFactory())
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    @Override
    public List<ConnectionRecord> findByPayerId(String payerId) {
        return readAll().stream().filter(r -> r.payerId().equals(payerId)).toList();
    }

    @Override
    public Optional<ConnectionRecord> findByPayerIdAndEnvironment(String payerId, Environment environment) {
        return readAll().stream()
                .filter(r -> r.payerId().equals(payerId) && r.environment() == environment)
                .findFirst();
    }

    @Override
    public List<ConnectionRecord> findAll() {
        return readAll();
    }

    @Override
    public void save(ConnectionRecord record) {
        lock.writeLock().lock();
        try {
            List<ConnectionRecord> all = new ArrayList<>(readAll());
            all.removeIf(r -> r.key().equals(record.key()));
            all.add(record);
            writeAll(all);
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void delete(String payerId, Environment environment) {
        lock.writeLock().lock();
        try {
            List<ConnectionRecord> all = new ArrayList<>(readAll());
            all.removeIf(r -> r.payerId().equals(payerId) && r.environment() == environment);
            writeAll(all);
        } finally {
            lock.writeLock().unlock();
        }
    }

    private List<ConnectionRecord> readAll() {
        lock.readLock().lock();
        try {
            if (!Files.exists(path)) {
                return List.of();
            }
            ConnectionRecord[] records = mapper.readValue(path.toFile(), ConnectionRecord[].class);
            return records == null ? List.of() : List.of(records);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed reading connection store at " + path, e);
        } finally {
            lock.readLock().unlock();
        }
    }

    private void writeAll(List<ConnectionRecord> records) {
        try {
            if (path.getParent() != null) {
                Files.createDirectories(path.getParent());
            }
            mapper.writeValue(path.toFile(), records);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing connection store at " + path, e);
        }
    }
}
