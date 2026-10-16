package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.Arrays;
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
 * <p>Windows refuses to replace a file that any other handle has open, even a
 * read-only one, so on Windows a {@link #save} or {@link #delete} waits briefly
 * (about 0.3 s in total) for another process's read to finish. If a reader keeps
 * the file open longer than that, the write fails with an
 * {@link UncheckedIOException} caused by an {@link AccessDeniedException} and the
 * file keeps its previous contents.
 *
 * <p>Reads are served from an in-memory copy of the parsed records, kept with
 * the raw file bytes it was parsed from. Every read still reads the file and
 * compares its bytes with the cached ones, re-parsing only when they differ,
 * so hand edits and other writers are seen on the next read. {@link #save}
 * and {@link #delete} refresh the cache with what they wrote. A read or parse
 * failure is thrown, never answered from the cache.
 *
 * <p><b>Single-process assumption:</b> there is no cross-process file lock.
 * One process (and ideally one store instance) must own the file; concurrent
 * writers in separate processes or instances can lose each other's updates.
 * Threads sharing one instance are safe.
 */
public final class FileBasedConnectionStore implements ConnectionStore {

    private static final int REPLACE_ATTEMPTS = 25;

    private final Path path;
    private final ObjectMapper mapper;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile Snapshot cache;

    public FileBasedConnectionStore(Path path) {
        this(path, defaultMapper());
    }

    // Visible for tests, which inject a mapper that fails mid-write or counts parses.
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
                cache = null;
                return List.of();
            }
            byte[] bytes = Files.readAllBytes(path);
            Snapshot cached = cache;
            if (cached != null && Arrays.equals(cached.bytes, bytes)) {
                return cached.records;
            }
            ConnectionRecord[] records = mapper.readValue(bytes, ConnectionRecord[].class);
            List<ConnectionRecord> parsed = records == null ? List.of() : List.of(records);
            cache = new Snapshot(bytes, parsed);
            return parsed;
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
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            mapper.writeValue(buffer, records);
            byte[] bytes = buffer.toByteArray();
            try (OutputStream out = Files.newOutputStream(tmp, StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                out.write(bytes);
                out.flush();
            }
            try (FileChannel ch = FileChannel.open(tmp, StandardOpenOption.WRITE)) {
                ch.force(true);
            }
            try {
                replace(tmp);
            } catch (AccessDeniedException e) {
                throw new UncheckedIOException("Failed writing connection store at " + path
                        + ": the file is open in another process or access is denied", e);
            }
            tmp = null;
            cache = new Snapshot(bytes, List.copyOf(records));
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

    /**
     * Moves {@code tmp} over the store file. Windows refuses to replace a file that another handle
     * has open, and a reader holds it only for one read, so a refused replace is retried briefly.
     */
    private void replace(Path tmp) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                move(tmp);
                return;
            } catch (AccessDeniedException e) {
                if (attempt >= REPLACE_ATTEMPTS) {
                    throw e;
                }
                try {
                    Thread.sleep(attempt);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw e;
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

    /** Parsed records together with the exact file bytes they came from. */
    private static final class Snapshot {
        private final byte[] bytes;
        private final List<ConnectionRecord> records;

        private Snapshot(byte[] bytes, List<ConnectionRecord> records) {
            this.bytes = bytes;
            this.records = records;
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
