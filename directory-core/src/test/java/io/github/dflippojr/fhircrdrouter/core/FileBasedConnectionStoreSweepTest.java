package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
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
