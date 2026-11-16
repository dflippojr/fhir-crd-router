package io.github.dflippojr.fhircrdrouter.core.internal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.DirectoryIteratorException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * The atomic file write shared by the file-backed stores: create a {@code <target>.*.tmp} file
 * next to the target, owner-only from creation (#99), write it and force it to disk, then move it
 * over the target, so a reader sees either the old or the new complete file and a crash or full
 * disk leaves the previous content intact. A writer killed before the move leaves its temporary
 * file behind; {@link #sweepOrphanedTemps} removes such files (#120).
 *
 * <p>Internal to this project: public only so that the store modules can call it. It is not part
 * of the library's API and may change in any release.
 */
public final class AtomicFiles {

    private static final int REPLACE_ATTEMPTS = 25;
    private static final String TEMP_SUFFIX = ".tmp";
    private static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

    private AtomicFiles() {
    }

    /** Creates a temporary file, as {@link Files#createTempFile(Path, String, String, FileAttribute[])}. */
    @FunctionalInterface
    public interface TempFileCreator {
        Path create(Path dir, String prefix, String suffix, FileAttribute<?>... attrs) throws IOException;
    }

    /** Moves a written temporary file over its target. */
    @FunctionalInterface
    public interface Mover {
        void move(Path tmp, Path target) throws IOException;
    }

    /** Deletes a file, as {@link Files#deleteIfExists(Path)}. */
    @FunctionalInterface
    public interface Deleter {
        void delete(Path file) throws IOException;
    }

    /** Whether {@code path}'s file system has POSIX permissions. */
    public static boolean posix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    /** Mode 600, for a create call where {@link #posix} holds. */
    public static FileAttribute<Set<PosixFilePermission>> ownerOnly() {
        return PosixFilePermissions.asFileAttribute(OWNER_ONLY);
    }

    /** Sets {@code path}'s mode to 600, for a file that already exists where {@link #posix} holds. */
    public static void restrictToOwner(Path path) throws IOException {
        Files.setPosixFilePermissions(path, OWNER_ONLY);
    }

    /**
     * As {@link #createOwnerOnlyTemp(TempFileCreator, Path, Path)} in {@code target}'s directory,
     * creating that directory and its parents first if they do not exist.
     */
    public static Path createOwnerOnlyTempNextTo(TempFileCreator tempFiles, Path target) throws IOException {
        Path dir = target.toAbsolutePath().getParent();
        Files.createDirectories(dir);
        return createOwnerOnlyTemp(tempFiles, dir, target);
    }

    /**
     * A {@code <target>.*.tmp} file in {@code dir}, owner-only from creation where POSIX permissions
     * exist (#99): the mode is set by the create call itself, never by a later chmod.
     */
    public static Path createOwnerOnlyTemp(TempFileCreator tempFiles, Path dir, Path target) throws IOException {
        String prefix = target.getFileName() + ".";
        if (posix(dir)) {
            return tempFiles.create(dir, prefix, TEMP_SUFFIX, ownerOnly());
        }
        return tempFiles.create(dir, prefix, TEMP_SUFFIX);
    }

    /** As {@link #sweepOrphanedTemps(Path, Path, Deleter)} with {@link Files#deleteIfExists}. */
    public static void sweepOrphanedTemps(Path dir, Path target) {
        sweepOrphanedTemps(dir, target, Files::deleteIfExists);
    }

    /**
     * Deletes the temporary files that writers of {@code target} left in {@code dir} when they were
     * killed before moving them into place (#120): the regular files whose name is
     * {@code <target file name>.} followed by one or more characters and {@code .tmp}, the names
     * {@link #createOwnerOnlyTemp} creates. Symbolic links and directories are left alone, links are
     * not followed and {@code dir} is not searched recursively.
     *
     * <p>The caller must be the only writer of {@code target}, or a temporary file another writer is
     * still filling is deleted under it. Best effort: a failure to list {@code dir} or to delete a
     * file is ignored, so the sweep never fails the write that runs it.
     */
    public static void sweepOrphanedTemps(Path dir, Path target, Deleter deleter) {
        String prefix = target.getFileName() + ".";
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(dir)) {
            for (Path entry : entries) {
                String name = entry.getFileName().toString();
                if (name.length() > prefix.length() + TEMP_SUFFIX.length()
                        && name.startsWith(prefix) && name.endsWith(TEMP_SUFFIX)) {
                    deleteIfRegularFile(entry, deleter);
                }
            }
        } catch (IOException | DirectoryIteratorException ignored) {
            // Best effort; the next write sweeps again.
        }
    }

    private static void deleteIfRegularFile(Path file, Deleter deleter) {
        try {
            if (Files.readAttributes(file, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS).isRegularFile()) {
                deleter.delete(file);
            }
        } catch (IOException ignored) {
            // Best effort: on Windows, for example, a file another handle has open cannot be deleted.
        }
    }

    /** Replaces the content of the existing {@code file} with {@code bytes} and forces it to disk. */
    public static void writeDurably(Path file, byte[] bytes) throws IOException {
        writeDurably(file, bytes, UnaryOperator.identity());
    }

    /** As {@link #writeDurably(Path, byte[])}, writing through {@code outputWrapper}. */
    public static void writeDurably(Path file, byte[] bytes, UnaryOperator<OutputStream> outputWrapper)
            throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
             OutputStream out = outputWrapper.apply(Channels.newOutputStream(channel))) {
            out.write(bytes);
            out.flush();
            channel.force(true);
        }
    }

    /** As {@link #replace(Path, Path, Mover)} with {@link #move}. */
    public static void replace(Path tmp, Path target) throws IOException {
        replace(tmp, target, AtomicFiles::move);
    }

    /**
     * Moves {@code tmp} over {@code target}. Windows refuses to replace a file that another handle
     * has open, and a reader holds it only for one read, so a refused replace is retried briefly:
     * 25 attempts, sleeping {@code attempt} milliseconds after each refusal
     * (about 0.3 s in total). An interrupt stops the retries, keeps the interrupt flag and throws
     * the last refusal.
     */
    public static void replace(Path tmp, Path target, Mover mover) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                mover.move(tmp, target);
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

    /** Moves {@code tmp} over {@code target} atomically, or replacing it where an atomic move is not supported. */
    public static void move(Path tmp, Path target) throws IOException {
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Deletes {@code tmp} if it is not null and exists, ignoring a failure. */
    public static void deleteQuietly(Path tmp) {
        if (tmp == null) {
            return;
        }
        try {
            Files.deleteIfExists(tmp);
        } catch (IOException ignored) {
            // Best effort; the original outcome is what matters.
        }
    }
}
