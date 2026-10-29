package io.github.dflippojr.fhircrdrouter.core.internal;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

class AtomicFilesTest {

    private static final boolean POSIX = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");

    @Test
    void temporaryFileIsOwnerOnlyTheMomentTheCreateCallReturns(@TempDir Path dir) throws IOException {
        assumeTrue(POSIX);
        List<String> requested = new ArrayList<>();
        List<String> found = new ArrayList<>();
        AtomicFiles.TempFileCreator checking = (parent, prefix, suffix, attrs) -> {
            requested.add(requested(attrs));
            Path tmp = Files.createTempFile(parent, prefix, suffix, attrs);
            found.add(PosixFilePermissions.toString(Files.getPosixFilePermissions(tmp)));
            return tmp;
        };

        Path tmp = AtomicFiles.createOwnerOnlyTemp(checking, dir, dir.resolve("store.yaml"));

        assertEquals(List.of("rw-------"), requested);
        assertEquals(List.of("rw-------"), found);
        assertEquals(dir, tmp.getParent());
        String name = tmp.getFileName().toString();
        assertTrue(name.startsWith("store.yaml.") && name.endsWith(".tmp"), name);
    }

    @Test
    void temporaryFileOnAFileSystemWithoutPosixIsCreatedWithoutAttributes(@TempDir Path dir) throws IOException {
        try (FileSystem zip = zipFileSystem(dir)) {
            Path zipDir = zip.getPath("/");
            List<String> requested = new ArrayList<>();
            List<String> prefixes = new ArrayList<>();
            AtomicFiles.TempFileCreator recording = (parent, prefix, suffix, attrs) -> {
                requested.add(requested(attrs));
                prefixes.add(prefix + "*" + suffix);
                return parent.resolve(prefix + "x" + suffix);
            };

            AtomicFiles.createOwnerOnlyTemp(recording, zipDir, zipDir.resolve("secrets.properties"));

            assertEquals(List.of("none"), requested);
            assertEquals(List.of("secrets.properties.*.tmp"), prefixes);
        }
    }

    @Test
    void posixFollowsTheFileSystemOfThePathAsked(@TempDir Path dir) throws IOException {
        assertEquals(POSIX, AtomicFiles.posix(dir));
        try (FileSystem zip = zipFileSystem(dir)) {
            assertFalse(AtomicFiles.posix(zip.getPath("/")));
        }
    }

    @Test
    void ownerOnlyAttributeIsReadWriteForTheOwnerAlone() {
        FileAttribute<Set<PosixFilePermission>> attr = AtomicFiles.ownerOnly();

        assertEquals("posix:permissions", attr.name());
        assertEquals("rw-------", PosixFilePermissions.toString(attr.value()));
    }

    @Test
    void writeDurablyReplacesTheWholeContent(@TempDir Path dir) throws IOException {
        Path file = Files.writeString(dir.resolve("f"), "a much longer previous content");

        AtomicFiles.writeDurably(file, "new".getBytes(StandardCharsets.UTF_8));

        assertEquals("new", Files.readString(file));
    }

    @Test
    void writeDurablyWritesThroughTheWrapper(@TempDir Path dir) throws IOException {
        Path file = Files.createFile(dir.resolve("f"));
        AtomicInteger written = new AtomicInteger();

        AtomicFiles.writeDurably(file, new byte[] {1, 2, 3}, out -> new FilterOutputStream(out) {
            @Override
            public void write(int b) throws IOException {
                written.incrementAndGet();
                super.write(b);
            }
        });

        assertEquals(3, written.get());
        assertArrayEquals(new byte[] {1, 2, 3}, Files.readAllBytes(file));
    }

    @Test
    void writeDurablyPassesOnAFailingWrite(@TempDir Path dir) throws IOException {
        Path file = Files.createFile(dir.resolve("f"));
        IOException failure = new IOException("disk full");

        IOException e = assertThrows(IOException.class, () -> AtomicFiles.writeDurably(file, new byte[] {1},
                out -> new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        throw failure;
                    }
                }));

        assertSame(failure, e);
    }

    @Test
    void writeDurablyNeedsAnExistingFile(@TempDir Path dir) {
        assertThrows(NoSuchFileException.class, () -> AtomicFiles.writeDurably(dir.resolve("missing"), new byte[] {1}));
    }

    @Test
    void moveReplacesTheTarget(@TempDir Path dir) throws IOException {
        Path tmp = Files.writeString(dir.resolve("f.tmp"), "new");
        Path target = Files.writeString(dir.resolve("f"), "old");

        AtomicFiles.move(tmp, target);

        assertEquals("new", Files.readString(target));
        assertFalse(Files.exists(tmp));
    }

    @Test
    void moveFallsBackToReplaceWhenAnAtomicMoveIsNotSupported(@TempDir Path dir) throws IOException {
        // A move into another file system provider cannot be atomic and throws AtomicMoveNotSupportedException.
        Path tmp = Files.writeString(dir.resolve("f.tmp"), "new");
        try (FileSystem zip = zipFileSystem(dir)) {
            Path target = Files.writeString(zip.getPath("/f"), "old");

            AtomicFiles.move(tmp, target);

            assertEquals("new", Files.readString(target));
        }
        assertFalse(Files.exists(tmp));
    }

    @Test
    void replaceRetriesARefusedMoveUntilItSucceeds(@TempDir Path dir) throws IOException {
        Path tmp = Files.writeString(dir.resolve("f.tmp"), "new");
        Path target = Files.writeString(dir.resolve("f"), "old");
        AtomicInteger attempts = new AtomicInteger();

        AtomicFiles.replace(tmp, target, refusing(3, attempts));

        assertEquals(4, attempts.get());
        assertEquals("new", Files.readString(target));
    }

    @Test
    void replaceGivesUpAfterTwentyFiveRefusals(@TempDir Path dir) throws IOException {
        Path tmp = Files.writeString(dir.resolve("f.tmp"), "new");
        Path target = Files.writeString(dir.resolve("f"), "old");
        AtomicInteger attempts = new AtomicInteger();

        assertThrows(AccessDeniedException.class,
                () -> AtomicFiles.replace(tmp, target, refusing(Integer.MAX_VALUE, attempts)));

        assertEquals(25, attempts.get());
        assertEquals("old", Files.readString(target));
        assertTrue(Files.exists(tmp));
    }

    @Test
    void replaceSleepsOneMillisecondMoreBeforeEachRetry(@TempDir Path dir) {
        Path tmp = dir.resolve("f.tmp");
        Path target = dir.resolve("f");
        List<Long> starts = new ArrayList<>();
        AtomicFiles.Mover refusing = (t, d) -> {
            starts.add(System.nanoTime());
            throw new AccessDeniedException(t + " -> " + d);
        };

        assertThrows(AccessDeniedException.class, () -> AtomicFiles.replace(tmp, target, refusing));

        // Thread.sleep(attempt) after attempt 1..24: at least 1 + 2 + ... + 24 = 300 ms in total.
        assertEquals(25, starts.size());
        for (int attempt = 1; attempt < starts.size(); attempt++) {
            long gapMillis = (starts.get(attempt) - starts.get(attempt - 1)) / 1_000_000;
            assertTrue(gapMillis >= attempt, "gap after attempt " + attempt + " was " + gapMillis + " ms");
        }
    }

    @Test
    void interruptDuringARetryStopsAndKeepsTheInterruptFlag(@TempDir Path dir) {
        AtomicInteger attempts = new AtomicInteger();
        AccessDeniedException refusal = new AccessDeniedException("refused");
        AtomicFiles.Mover interrupting = (tmp, target) -> {
            attempts.incrementAndGet();
            Thread.currentThread().interrupt();
            throw refusal;
        };

        try {
            AccessDeniedException e = assertThrows(AccessDeniedException.class,
                    () -> AtomicFiles.replace(dir.resolve("f.tmp"), dir.resolve("f"), interrupting));

            assertSame(refusal, e);
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();
        }
        assertEquals(1, attempts.get());
    }

    @Test
    void replaceDoesNotRetryOtherFailures(@TempDir Path dir) {
        AtomicInteger attempts = new AtomicInteger();
        IOException failure = new IOException("disk gone");

        IOException e = assertThrows(IOException.class, () -> AtomicFiles.replace(dir.resolve("f.tmp"),
                dir.resolve("f"), (tmp, target) -> {
                    attempts.incrementAndGet();
                    throw failure;
                }));

        assertSame(failure, e);
        assertEquals(1, attempts.get());
    }

    @Test
    void replaceWithoutAMoverUsesTheAtomicMove(@TempDir Path dir) throws IOException {
        Path tmp = Files.writeString(dir.resolve("f.tmp"), "new");
        Path target = Files.writeString(dir.resolve("f"), "old");

        AtomicFiles.replace(tmp, target);

        assertEquals("new", Files.readString(target));
        assertFalse(Files.exists(tmp));
    }

    @Test
    void deleteQuietlyIgnoresNull() {
        AtomicFiles.deleteQuietly(null);
    }

    @Test
    void deleteQuietlyDeletesAFileAndIgnoresAMissingOne(@TempDir Path dir) throws IOException {
        Path tmp = Files.createFile(dir.resolve("f.tmp"));

        AtomicFiles.deleteQuietly(tmp);
        AtomicFiles.deleteQuietly(tmp);

        assertFalse(Files.exists(tmp));
    }

    @Test
    void deleteQuietlySwallowsAFailedDelete(@TempDir Path dir) throws IOException {
        Path notEmpty = Files.createDirectory(dir.resolve("d"));
        Files.createFile(notEmpty.resolve("child"));

        AtomicFiles.deleteQuietly(notEmpty);

        assertTrue(Files.exists(notEmpty));
    }

    /** A move that is refused {@code refusals} times, as Windows refuses it while a reader has the file open. */
    private static AtomicFiles.Mover refusing(int refusals, AtomicInteger attempts) {
        return (tmp, target) -> {
            if (attempts.incrementAndGet() <= refusals) {
                throw new AccessDeniedException(tmp + " -> " + target);
            }
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        };
    }

    private static FileSystem zipFileSystem(Path dir) throws IOException {
        return FileSystems.newFileSystem(URI.create("jar:" + dir.resolve("fs.zip").toUri()), Map.of("create", "true"));
    }

    /** The POSIX permissions a create call was given, or "none". */
    @SuppressWarnings("unchecked")
    private static String requested(FileAttribute<?>... attrs) {
        for (FileAttribute<?> attr : attrs) {
            if (attr.name().equals("posix:permissions")) {
                return PosixFilePermissions.toString((Set<PosixFilePermission>) attr.value());
            }
        }
        return "none";
    }
}
