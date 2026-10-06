package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Default v1 {@link ConnectionStore}: connection records as a flat YAML
 * list on disk. Whole-file read + rewrite on every mutation — fine for a
 * handful to a few hundred payer records; not meant to scale beyond that.
 *
 * <p>Each write goes to a temporary file ({@code <name>.*.tmp}) in the same
 * directory, is flushed to disk, and is then moved over the target, so a
 * crash or full disk never leaves a truncated file behind.
 *
 * <p><b>Single-process assumption:</b> there is no cross-process file lock.
 * One process (and ideally one store instance) must own the file; concurrent
 * writers in separate processes or instances can lose each other's updates.
 * Threads sharing one instance are safe.
 */
public final class FileBasedConnectionStore implements ConnectionStore {

    private final Path path;
    private final ObjectMapper mapper;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public FileBasedConnectionStore(Path path) {
        this(path, defaultMapper());
    }

    // Visible for tests, which inject a mapper that fails mid-write.
    FileBasedConnectionStore(Path path, ObjectMapper mapper) {
        this.path = path;
        this.mapper = mapper;
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper(new YAMLFactory())
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
        Path dir = path.toAbsolutePath().getParent();
        Path tmp = null;
        try {
            Files.createDirectories(dir);
            tmp = Files.createTempFile(dir, path.getFileName() + ".", ".tmp");
            applyPermissions(tmp);
            try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                mapper.writeValue(out, records);
                out.flush();
            }
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            move(tmp);
            tmp = null;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing connection store at " + path, e);
        } finally {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // Best effort; the original failure is what matters.
                }
            }
        }
    }

    private void move(Path tmp) throws IOException {
        try {
            Files.move(tmp, path, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Mirror the existing file's mode, else owner-only, where POSIX permissions exist. */
    private void applyPermissions(Path tmp) throws IOException {
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            return;
        }
        Set<PosixFilePermission> perms = Files.exists(path)
                ? Files.getPosixFilePermissions(path)
                : PosixFilePermissions.fromString("rw-------");
        Files.setPosixFilePermissions(tmp, perms);
    }
}
