package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #120: a {@code put} or {@code remove} removes, under the store lock, the
 * {@code secrets.properties.*.tmp} and {@code key.bin.*.tmp} files that writers killed mid-write
 * left, and nothing else.
 */
class EncryptedLocalCredentialProviderSweepTest {

    private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    @Test
    void putRemovesOrphanedTemporaryFilesAndNothingElse(@TempDir Path dir, @TempDir Path outside) throws IOException {
        var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        provider.put("existing", "synthetic-secret-existing");
        Fixed fixed = Fixed.read(dir);
        Planted planted = plant(dir, outside);

        provider.put("new", "synthetic-secret-new");

        planted.assertOnlyOrphansRemoved();
        fixed.assertUntouched();
        var fresh = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        assertEquals(Optional.of("synthetic-secret-new"), fresh.resolve("new"));
        assertEquals(Optional.of("synthetic-secret-existing"), fresh.resolve("existing"));
    }

    @Test
    void firstPutRemovesOrphanedTemporaryFilesOfAKilledKeyCreation(@TempDir Path dir, @TempDir Path outside)
            throws IOException {
        Planted planted = plant(dir, outside);

        new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO).put("first", "synthetic-secret-first");

        planted.assertOnlyOrphansRemoved();
        assertEquals(Optional.of("synthetic-secret-first"),
                new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO).resolve("first"));
    }

    @Test
    void removeThatRewritesTheFileRemovesOrphanedTemporaryFilesAndNothingElse(@TempDir Path dir, @TempDir Path outside)
            throws IOException {
        var provider = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        provider.put("kept", "synthetic-secret-kept");
        provider.put("gone", "synthetic-secret-gone");
        Planted planted = plant(dir, outside);
        Fixed fixed = Fixed.read(dir);

        provider.remove("gone");

        planted.assertOnlyOrphansRemoved();
        fixed.assertUntouched();
        var fresh = new EncryptedLocalCredentialProvider(dir, null, Duration.ZERO);
        assertEquals(Optional.empty(), fresh.resolve("gone"));
        assertEquals(Optional.of("synthetic-secret-kept"), fresh.resolve("kept"));
    }

    /** {@code key.bin} and {@code secrets.lock}, which a sweep never touches. */
    private record Fixed(Path dir, byte[] key, byte[] lock) {
        static Fixed read(Path dir) throws IOException {
            return new Fixed(dir, Files.readAllBytes(dir.resolve("key.bin")), Files.readAllBytes(dir.resolve("secrets.lock")));
        }

        void assertUntouched() throws IOException {
            assertArrayEquals(key, Files.readAllBytes(dir.resolve("key.bin")), "key.bin changed");
            assertArrayEquals(lock, Files.readAllBytes(dir.resolve("secrets.lock")), "secrets.lock changed");
        }
    }

    /** Orphans of both store files and the files next to them that a sweep must leave alone. */
    private static Planted plant(Path dir, Path outside) throws IOException {
        List<Path> orphans = List.of(
                write(dir.resolve("secrets.properties.5747083215558029025.tmp")),
                write(dir.resolve("key.bin.6440188173590723421.tmp")));
        List<Path> survivors = new ArrayList<>(List.of(
                write(dir.resolve("other.properties.123.tmp")),
                write(dir.resolve("secrets.properties.tmp")),
                write(dir.resolve("key.bin.tmp")),
                write(dir.resolve("secrets.properties.bak")),
                write(dir.resolve("secrets.lock.1.tmp"))));
        survivors.add(Files.createDirectory(dir.resolve("secrets.properties.42.tmp")));
        survivors.add(Files.createDirectory(dir.resolve("key.bin.42.tmp")));
        Path linkTarget = null;
        if (POSIX) {
            linkTarget = write(outside.resolve("target-of-link"));
            Files.createSymbolicLink(dir.resolve("secrets.properties.7.tmp"), linkTarget);
            Files.createSymbolicLink(dir.resolve("key.bin.7.tmp"), linkTarget);
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
}
