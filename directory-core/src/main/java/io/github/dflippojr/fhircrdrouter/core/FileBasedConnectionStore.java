package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.dflippojr.fhircrdrouter.core.internal.AtomicFiles;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
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
 * <p>A file with no YAML content (empty, whitespace or comments only) reads as
 * no records, like a missing file, and {@link #save} writes into it.
 *
 * <p><b>Single-process assumption:</b> there is no cross-process file lock.
 * One process (and ideally one store instance) must own the file; concurrent
 * writers in separate processes or instances can lose each other's updates.
 * Threads sharing one instance are safe.
 */
public final class FileBasedConnectionStore implements ConnectionStore {

    private final Path path;
    private final ObjectMapper mapper;
    private final AtomicFiles.Mover mover;
    private final AtomicFiles.TempFileCreator tempFiles;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile Snapshot cache;

    public FileBasedConnectionStore(Path path) {
        this(path, defaultMapper());
    }

    // Visible for tests, which inject a mapper that fails mid-write or counts parses.
    FileBasedConnectionStore(Path path, ObjectMapper mapper) {
        this(path, mapper, AtomicFiles::move);
    }

    // Visible for tests, which inject a move that is refused the way Windows refuses it.
    FileBasedConnectionStore(Path path, ObjectMapper mapper, AtomicFiles.Mover mover) {
        this(path, mapper, mover, Files::createTempFile);
    }

    // Visible for tests, which check each temporary file's permissions the moment it exists.
    FileBasedConnectionStore(Path path, ObjectMapper mapper, AtomicFiles.Mover mover,
                             AtomicFiles.TempFileCreator tempFiles) {
        this.path = path;
        this.mapper = mapper;
        this.mover = mover;
        this.tempFiles = tempFiles;
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
            // No match: leave the file alone, so a no-op delete neither creates it nor
            // risks a refused replace on Windows.
            if (all.removeIf(r -> r.payerId().equals(payerId) && r.environment() == environment)) {
                writeAll(all);
            }
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
            ConnectionRecord[] records = hasContent(bytes) ? mapper.readValue(bytes, ConnectionRecord[].class) : null;
            List<ConnectionRecord> parsed = records == null ? List.of() : List.of(records);
            cache = new Snapshot(bytes, parsed);
            return parsed;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed reading connection store at " + path, e);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Whether the YAML holds a value at all. An empty, whitespace-only or comment-only file has no
     * token, and {@code readValue} rejects it instead of returning null, so it is answered here as
     * no records, the same as a missing file or {@code null} (#193). Anything else, including a
     * malformed document, goes on to {@code readValue} and fails there. Blank text is checked first
     * because the YAML scanner rejects a tab where a token could start, so a tab-only file would
     * otherwise fail.
     */
    private boolean hasContent(byte[] bytes) throws IOException {
        if (new String(bytes, StandardCharsets.UTF_8).isBlank()) {
            return false;
        }
        try (JsonParser parser = mapper.createParser(bytes)) {
            return parser.nextToken() != null;
        }
    }

    private void writeAll(List<ConnectionRecord> records) {
        Path dir = path.toAbsolutePath().getParent();
        Path tmp = null;
        try {
            Files.createDirectories(dir);
            tmp = AtomicFiles.createOwnerOnlyTemp(tempFiles, dir, path);
            mirrorPermissions(tmp);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            mapper.writeValue(buffer, records);
            byte[] bytes = buffer.toByteArray();
            AtomicFiles.writeDurably(tmp, bytes);
            try {
                AtomicFiles.replace(tmp, path, mover);
            } catch (AccessDeniedException e) {
                throw new UncheckedIOException("Failed writing connection store at " + path
                        + ": the file is open in another process or access is denied", e);
            }
            tmp = null;
            cache = new Snapshot(bytes, List.copyOf(records));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing connection store at " + path, e);
        } finally {
            AtomicFiles.deleteQuietly(tmp);
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

    /** Gives the temporary file the existing store file's mode, where POSIX permissions exist. */
    private void mirrorPermissions(Path tmp) throws IOException {
        if (AtomicFiles.posix(path) && Files.exists(path)) {
            Files.setPosixFilePermissions(tmp, Files.getPosixFilePermissions(path));
        }
    }
}
