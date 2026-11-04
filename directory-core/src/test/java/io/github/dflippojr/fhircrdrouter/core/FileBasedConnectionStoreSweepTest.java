package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.github.dflippojr.fhircrdrouter.core.internal.AtomicFiles;

import java.io.IOException;
import java.nio.file.AccessDeniedException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #120: a write removes the {@code <name>.*.tmp} files that writers killed mid-write left next to
 * the store file, and nothing else.
 */
class FileBasedConnectionStoreSweepTest {

    private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    private static final String NAME = "connections.yaml";

    @Test
    void saveRemovesOrphanedTemporaryFilesAndNothingElse(@TempDir Path dir, @TempDir Path outside) throws IOException {
        Planted planted = plant(dir, outside);

        new FileBasedConnectionStore(dir.resolve(NAME)).save(record("PAYER-1"));

        planted.assertOnlyOrphansRemoved();
        assertEquals(List.of(record("PAYER-1")), new FileBasedConnectionStore(dir.resolve(NAME)).findAll());
    }

    @Test
    void deleteRemovesOrphanedTemporaryFilesAndNothingElse(@TempDir Path dir, @TempDir Path outside) throws IOException {
        FileBasedConnectionStore store = new FileBasedConnectionStore(dir.resolve(NAME));
        store.save(record("PAYER-1"));
        store.save(record("PAYER-2"));
        Planted planted = plant(dir, outside);

        store.delete("PAYER-2", Environment.SANDBOX);

        planted.assertOnlyOrphansRemoved();
        assertEquals(List.of(record("PAYER-1")), new FileBasedConnectionStore(dir.resolve(NAME)).findAll());
    }

    @Test
    void aSweepThatCannotDeleteNeverFailsTheWrite(@TempDir Path dir) throws IOException {
        Path orphan = write(dir.resolve(NAME + ".1.tmp"));
        List<Path> refused = new ArrayList<>();
        AtomicFiles.Deleter refusing = file -> {
            refused.add(file.getFileName());
            throw new AccessDeniedException(file.toString());
        };
        var store = new FileBasedConnectionStore(dir.resolve(NAME), mapper(), AtomicFiles::move,
                Files::createTempFile, refusing);

        store.save(record("PAYER-1"));
        store.save(record("PAYER-2"));
        store.delete("PAYER-1", Environment.SANDBOX);

        assertEquals(List.of(record("PAYER-2")), new FileBasedConnectionStore(dir.resolve(NAME)).findAll());
        assertEquals(List.of(orphan.getFileName(), orphan.getFileName(), orphan.getFileName()), refused);
        assertTrue(Files.exists(orphan));
    }

    @Test
    void readsRemoveNothing(@TempDir Path dir) throws IOException {
        Path file = dir.resolve(NAME);
        new FileBasedConnectionStore(file).save(record("PAYER-1"));
        Path orphan = write(dir.resolve(NAME + ".1.tmp"));
        var store = new FileBasedConnectionStore(file);

        assertEquals(1, store.findAll().size());
        assertEquals(1, store.findByPayerId("PAYER-1").size());
        assertTrue(store.findByPayerIdAndEnvironment("PAYER-1", Environment.SANDBOX).isPresent());
        // A delete that matches nothing writes nothing, so it does not sweep either.
        store.delete("PAYER-9", Environment.SANDBOX);

        assertTrue(Files.exists(orphan), "a read removed an orphaned temporary file");
    }

    private static ObjectMapper mapper() {
        return new ObjectMapper(new YAMLFactory())
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .enable(SerializationFeature.INDENT_OUTPUT);
    }

    /** Orphans of {@link #NAME} and the files next to them that a sweep must leave alone. */
    private static Planted plant(Path dir, Path outside) throws IOException {
        List<Path> orphans = List.of(
                write(dir.resolve(NAME + ".5747083215558029025.tmp")),
                write(dir.resolve(NAME + ".x.tmp")));
        List<Path> survivors = new ArrayList<>(List.of(
                write(dir.resolve("other.yaml.123.tmp")),
                write(dir.resolve(NAME + ".tmp")),
                write(dir.resolve(NAME + ".bak")),
                write(dir.resolve("prefix-" + NAME + ".1.tmp"))));
        Path directory = Files.createDirectory(dir.resolve(NAME + ".42.tmp"));
        survivors.add(directory);
        Path linkTarget = null;
        if (POSIX) {
            linkTarget = write(outside.resolve("target-of-link"));
            Files.createSymbolicLink(dir.resolve(NAME + ".7.tmp"), linkTarget);
        }
        return new Planted(orphans, survivors, linkTarget);
    }

    private static Path write(Path file) throws IOException {
        return Files.writeString(file, "planted " + file.getFileName(), StandardCharsets.UTF_8);
    }

    private record Planted(List<Path> orphans, List<Path> survivors, Path linkTarget) {
        void assertOnlyOrphansRemoved() throws IOException {
            for (Path orphan : orphans) {
                assertFalse(Files.exists(orphan, LinkOption.NOFOLLOW_LINKS), "orphan left behind: " + orphan.getFileName());
            }
            for (Path survivor : survivors) {
                assertTrue(Files.exists(survivor, LinkOption.NOFOLLOW_LINKS), "removed: " + survivor.getFileName());
                if (Files.isRegularFile(survivor)) {
                    assertEquals("planted " + survivor.getFileName(), Files.readString(survivor, StandardCharsets.UTF_8));
                }
            }
            if (linkTarget != null) {
                assertEquals("planted target-of-link", Files.readString(linkTarget, StandardCharsets.UTF_8),
                        "the symlink's target outside the store directory was touched");
            }
        }
    }

    static ConnectionRecord record(String payerId) {
        Instant created = Instant.parse("2026-01-01T00:00:00Z");
        return ConnectionRecord.builder()
                .payerId(payerId)
                .displayName("Synthetic payer " + payerId)
                .environment(Environment.SANDBOX)
                .baseUrl("https://" + payerId.toLowerCase() + ".payer.example.test/cds")
                .authType(AuthType.NONE)
                .credentialRef("synthetic-ref-" + payerId)
                .createdAt(created)
                .updatedAt(created)
                .build();
    }
}
