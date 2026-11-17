package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
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
 * crash or full disk never leaves a truncated file behind. A writer killed
 * before the move leaves its temporary file behind; the next {@link #save} or
 * {@link #delete} that writes the file removes every such file under its write
 * lock (#120). That relies on the single-process assumption below. Reads remove
 * nothing.
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
 * <p><b>One unreadable entry does not break the others (#231).</b> The file is
 * read as a YAML list of raw nodes and each node is bound on its own. A node
 * that does not bind (a field its auth type requires is missing, or it has a
 * property or enum constant this version does not know, as a file written by a
 * newer version can) is kept as an {@link InvalidEntry}, listed by
 * {@link #invalidEntries()}. Other payers resolve as usual, and {@link #findAll}
 * leaves the entry out. A lookup that would include it, by its payerId or by
 * its key, throws {@link InvalidConnectionRecordException} naming the payer,
 * the environment and the problem class, never a field value. An entry whose
 * environment this version does not know matches no key; only
 * {@link #findByPayerId} and {@link #invalidEntries()} see it. A file that is
 * not YAML, or not a list, still fails every read.
 *
 * <p>Writes are lossless at node level: every entry {@link #save} or
 * {@link #delete} does not touch is written back as it was read, readable or
 * not, with any field this version does not know. {@code save} lays the
 * record's fields over its key's stored node, in place, so a newer field on
 * that entry survives an older writer's update, and appends a new key at the
 * end. {@code delete} removes every entry with the key, including an unreadable
 * one, which is how the API clears it. YAML comments and formatting are not
 * kept by a rewrite.
 *
 * <p><b>Single-process assumption:</b> there is no cross-process file lock.
 * One process (and ideally one store instance) must own the file; concurrent
 * writers in separate processes or instances can lose each other's updates.
 * They can also fail: a writer's sweep may delete the temporary file another
 * instance is still filling, and that instance's write then fails with an
 * {@link UncheckedIOException} and leaves the file as it was. Threads sharing
 * one instance are safe. A {@link #save} or {@link #delete} also sweeps any
 * {@code <name>.*.tmp} as an orphan, so keep the file in a directory where no
 * other file name extends this one's (for example {@code a.yaml} and
 * {@code a.yaml.x}).
 */
public final class FileBasedConnectionStore implements ConnectionStore {

    private final Path path;
    private final ObjectMapper mapper;
    private final AtomicFiles.Mover mover;
    private final AtomicFiles.TempFileCreator tempFiles;
    private final AtomicFiles.Deleter sweepDeleter;
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
        this(path, mapper, mover, tempFiles, Files::deleteIfExists);
    }

    // Visible for tests, which make the sweep of orphaned temporary files fail.
    FileBasedConnectionStore(Path path, ObjectMapper mapper, AtomicFiles.Mover mover,
                             AtomicFiles.TempFileCreator tempFiles, AtomicFiles.Deleter sweepDeleter) {
        this.path = path;
        this.mapper = mapper;
        this.mover = mover;
        this.tempFiles = tempFiles;
        this.sweepDeleter = sweepDeleter;
    }

    private static ObjectMapper defaultMapper() {
        return new ObjectMapper(new YAMLFactory())
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    /**
     * The payer's records. Throws {@link InvalidConnectionRecordException} when an entry this version
     * cannot read names this payer, since the answer would otherwise be silently incomplete.
     */
    @Override
    public List<ConnectionRecord> findByPayerId(String payerId) {
        Snapshot snapshot = readAll();
        for (InvalidEntry invalid : snapshot.invalid) {
            if (invalid.hasPayerId(payerId)) {
                throw invalidRecord(invalid);
            }
        }
        return snapshot.records.stream().filter(r -> r.payerId().equals(payerId)).toList();
    }

    /**
     * The record for one key. Throws {@link InvalidConnectionRecordException} when an entry this
     * version cannot read has this key, so a broken record never reads as absent (#231).
     */
    @Override
    public Optional<ConnectionRecord> findByPayerIdAndEnvironment(String payerId, Environment environment) {
        Snapshot snapshot = readAll();
        for (InvalidEntry invalid : snapshot.invalid) {
            if (invalid.hasPayerId(payerId) && environment != null && invalid.environment() == environment) {
                throw invalidRecord(invalid);
            }
        }
        return snapshot.records.stream()
                .filter(r -> r.payerId().equals(payerId) && r.environment() == environment)
                .findFirst();
    }

    /** Every record this version can read; entries it cannot read are left out (#231). */
    @Override
    public List<ConnectionRecord> findAll() {
        return readAll().records;
    }

    /**
     * The stored entries this version cannot read, in file order, for an admin tool to show (#231).
     * Empty when every entry binds. Not on {@link ConnectionStore}: it describes this file format.
     * A read that fails as a whole (the file is not YAML, or not a list) throws, as the lookups do.
     */
    public List<InvalidEntry> invalidEntries() {
        return readAll().invalid;
    }

    /**
     * Writes the record over its key's stored entry, in place, or appends it when the key has none.
     * The record's fields are laid over the stored entry's node, so a property this version does not
     * know survives the update (#231). Every other entry, readable or not, is written back as read.
     * A later entry with the same key is dropped, as before.
     */
    @Override
    public void save(ConnectionRecord record) {
        lock.writeLock().lock();
        try {
            List<Entry> entries = readAll().entries;
            ObjectNode known = mapper.valueToTree(record);
            List<JsonNode> nodes = new ArrayList<>();
            boolean placed = false;
            for (Entry entry : entries) {
                if (!entry.hasKey(record.payerId(), record.environment())) {
                    nodes.add(entry.node);
                } else if (!placed) {
                    nodes.add(overlay(entry.node, known));
                    placed = true;
                }
            }
            if (!placed) {
                nodes.add(known);
            }
            writeAll(nodes);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Removes every stored entry with this key, including one this version cannot read, which makes
     * delete the way to clear a broken entry through the API (#231). Other entries are written back as
     * read.
     */
    @Override
    public void delete(String payerId, Environment environment) {
        lock.writeLock().lock();
        try {
            List<Entry> entries = readAll().entries;
            List<JsonNode> kept = entries.stream()
                    .filter(entry -> !entry.hasKey(payerId, environment))
                    .map(entry -> entry.node)
                    .toList();
            // No match: leave the file alone, so a no-op delete neither creates it nor
            // risks a refused replace on Windows.
            if (kept.size() != entries.size()) {
                writeAll(kept);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * The stored node with the record's fields laid over it; fields this version does not know stay.
     * A node with a key is always an object, since a scalar or null list item has no payerId.
     */
    private static JsonNode overlay(JsonNode stored, ObjectNode known) {
        ObjectNode merged = ((ObjectNode) stored).deepCopy();
        merged.setAll(known);
        return merged;
    }

    private InvalidConnectionRecordException invalidRecord(InvalidEntry invalid) {
        return new InvalidConnectionRecordException("Connection record cannot be read: " + describe(invalid)
                + " in " + path, invalid.payerId(), invalid.environment(), invalid.problem());
    }

    /** Names the entry by key, position and problem class only, never by a field value. */
    private static String describe(InvalidEntry invalid) {
        return "payerId=" + invalid.payerId()
                + " environment=" + (invalid.environment() == null ? "(unreadable)" : invalid.environment())
                + " (entry " + invalid.index() + ", " + invalid.problem() + ")";
    }

    private Snapshot readAll() {
        lock.readLock().lock();
        try {
            if (!Files.exists(path)) {
                cache = null;
                return Snapshot.EMPTY;
            }
            byte[] bytes = Files.readAllBytes(path);
            Snapshot cached = cache;
            if (cached != null && Arrays.equals(cached.bytes, bytes)) {
                return cached;
            }
            Snapshot parsed = parse(bytes);
            cache = parsed;
            return parsed;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed reading connection store at " + path, e);
        } finally {
            lock.readLock().unlock();
        }
    }

    /**
     * Reads the file as a YAML list of raw nodes, then binds each node on its own, so one entry this
     * version cannot read leaves the others usable (#231). A file that is not a list, or not YAML,
     * still fails as a whole.
     */
    private Snapshot parse(byte[] bytes) throws IOException {
        // StoredYaml keeps each unquoted scalar as it was spelled, for binding and for the rewrite.
        StoredYaml.Document document = hasContent(bytes) ? mapper.readValue(bytes, StoredYaml.Document.class) : null;
        // A null document (null, ~) never reaches the deserializer: readValue answers it as null.
        JsonNode root = document == null ? null : document.root();
        if (root == null) {
            return bind(bytes, List.of());
        }
        if (!root.isArray()) {
            throw new IOException("expected a YAML list of connection records, found " + root.getNodeType());
        }
        List<JsonNode> nodes = new ArrayList<>();
        root.forEach(nodes::add);
        return bind(bytes, nodes);
    }

    /** Binds each node on its own; a node that does not bind is kept as an invalid entry. */
    private Snapshot bind(byte[] bytes, List<JsonNode> nodes) {
        List<Entry> entries = new ArrayList<>();
        List<ConnectionRecord> records = new ArrayList<>();
        List<InvalidEntry> invalid = new ArrayList<>();
        for (int index = 0; index < nodes.size(); index++) {
            JsonNode node = nodes.get(index);
            String problem;
            try {
                ConnectionRecord record = mapper.treeToValue(StoredYaml.forBinding(node), ConnectionRecord.class);
                if (record != null) {
                    records.add(record);
                    entries.add(new Entry(node, record.payerId(), record.environment()));
                    continue;
                }
                problem = "NullEntry";
            } catch (JsonProcessingException | IllegalArgumentException e) {
                problem = rootCause(e).getClass().getSimpleName();
            }
            InvalidEntry entry = new InvalidEntry(index, keyFieldOf(node, "payerId", String.class),
                    keyFieldOf(node, "environment", Environment.class), problem);
            invalid.add(entry);
            entries.add(new Entry(node, entry.payerId(), entry.environment()));
        }
        return new Snapshot(bytes, List.copyOf(entries), List.copyOf(records), List.copyOf(invalid));
    }

    private static Throwable rootCause(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null) {
            root = root.getCause();
        }
        return root;
    }

    /**
     * One key field of an entry that did not bind, read with the same rules as the record binding (so
     * {@code environment: 2} is {@code PRODUCTION}, as Jackson binds it, and a scalar payerId is text),
     * or null when it is missing, null or does not bind. A list item that is not an object has neither.
     */
    private <T> T keyFieldOf(JsonNode node, String field, Class<T> type) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return null;
        }
        try {
            return mapper.treeToValue(StoredYaml.forBinding(value), type);
        } catch (JsonProcessingException | IllegalArgumentException e) {
            return null;
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

    private void writeAll(List<JsonNode> nodes) {
        Path dir = path.toAbsolutePath().getParent();
        Path tmp = null;
        try {
            // Under the write lock and, by the single-process assumption, the only writer of this
            // file: every <name>.*.tmp here is a killed writer's orphan (#120). A missing directory
            // has none, and the sweep ignores it; the temp-file call below creates it.
            AtomicFiles.sweepOrphanedTemps(dir, path, sweepDeleter);
            tmp = AtomicFiles.createOwnerOnlyTempNextTo(tempFiles, path);
            mirrorPermissions(tmp);
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            ArrayNode list = mapper.createArrayNode();
            list.addAll(nodes);
            mapper.writeValue(buffer, list);
            byte[] bytes = buffer.toByteArray();
            AtomicFiles.writeDurably(tmp, bytes);
            try {
                AtomicFiles.replace(tmp, path, mover);
            } catch (AccessDeniedException e) {
                throw new UncheckedIOException("Failed writing connection store at " + path
                        + ": the file is open in another process or access is denied", e);
            }
            tmp = null;
            cache = bind(bytes, nodes);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing connection store at " + path, e);
        } finally {
            AtomicFiles.deleteQuietly(tmp);
        }
    }

    /**
     * An entry of the stored list that this version cannot bind to a {@link ConnectionRecord} (#231).
     * It names the entry and the problem, never a field value.
     *
     * @param index the entry's zero-based position in the stored list
     * @param payerId the entry's {@code payerId}, or {@code null} when it has none this version can read
     * @param environment the entry's environment, or {@code null} when it has none this version knows
     * @param problem the simple class name of the exception that stopped the entry binding, or
     *     {@code NullEntry} for an empty list item
     */
    public record InvalidEntry(int index, String payerId, Environment environment, String problem) {
        boolean hasPayerId(String other) {
            return payerId != null && payerId.equals(other);
        }
    }

    /**
     * One item of the stored list: its node as read, never modified, and its key, which is null where
     * this version cannot read it.
     */
    private record Entry(JsonNode node, String payerId, Environment environment) {
        boolean hasKey(String otherPayerId, Environment otherEnvironment) {
            // A null payerId or environment matched nothing before #231 and must not throw, nor match an entry
            // whose payerId or environment this version cannot read.
            return payerId != null && payerId.equals(otherPayerId)
                    && environment != null && otherEnvironment == environment;
        }
    }

    /** What the file held, together with the exact file bytes it came from. */
    private static final class Snapshot {
        static final Snapshot EMPTY = new Snapshot(new byte[0], List.of(), List.of(), List.of());

        private final byte[] bytes;
        private final List<Entry> entries;
        private final List<ConnectionRecord> records;
        private final List<InvalidEntry> invalid;

        private Snapshot(byte[] bytes, List<Entry> entries, List<ConnectionRecord> records, List<InvalidEntry> invalid) {
            this.bytes = bytes;
            this.entries = entries;
            this.records = records;
            this.invalid = invalid;
        }
    }

    /** Gives the temporary file the existing store file's mode, where POSIX permissions exist. */
    private void mirrorPermissions(Path tmp) throws IOException {
        if (AtomicFiles.posix(path) && Files.exists(path)) {
            Files.setPosixFilePermissions(tmp, Files.getPosixFilePermissions(path));
        }
    }
}
