package io.github.dflippojr.fhircrdrouter.core.internal;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;
import java.util.function.UnaryOperator;

/**
 * The atomic file write shared by the file-backed stores: create a {@code <target>.*.tmp} file
 * next to the target, owner-only from creation (#99), write it and force it to disk, then move it
 * over the target, so a reader sees either the old or the new complete file and a crash or full
 * disk leaves the previous content intact.
 *
 * <p>Internal to this project: public only so that the store modules can call it. It is not part
 * of the library's API and may change in any release.
 */
public final class AtomicFiles {

    private static final int REPLACE_ATTEMPTS = 25;
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

    /** Whether {@code path}'s file system has POSIX permissions. */
    public static boolean posix(Path path) {
        return path.getFileSystem().supportedFileAttributeViews().contains("posix");
    }

    /** Mode 600, for a create call where {@link #posix} holds. */
    public static FileAttribute<Set<PosixFilePermission>> ownerOnly() {
        return PosixFilePermissions.asFileAttribute(OWNER_ONLY);
    }

    /**
     * A {@code <target>.*.tmp} file in {@code dir}, owner-only from creation where POSIX permissions
     * exist (#99): the mode is set by the create call itself, never by a later chmod.
     */
    public static Path createOwnerOnlyTemp(TempFileCreator tempFiles, Path dir, Path target) throws IOException {
        String prefix = target.getFileName() + ".";
        if (posix(dir)) {
            return tempFiles.create(dir, prefix, ".tmp", ownerOnly());
        }
        return tempFiles.create(dir, prefix, ".tmp");
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
