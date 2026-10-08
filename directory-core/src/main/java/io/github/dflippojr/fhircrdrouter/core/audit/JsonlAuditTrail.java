package io.github.dflippojr.fhircrdrouter.core.audit;

import io.github.dflippojr.fhircrdrouter.core.Environment;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.OverlappingFileLockException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Clock;
import java.util.EnumSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/** Opt-in, one writer per file. No business actions are instrumented by this foundation. */
public final class JsonlAuditTrail implements AuditSink, AutoCloseable {
    private final Clock clock;
    private final FileChannel channel;
    private final FileLock fileLock;
    private final Appender appender;
    private boolean poisoned;

    @FunctionalInterface
    interface Appender { void append(FileChannel channel, byte[] line) throws IOException; }

    public JsonlAuditTrail(Path path, Clock clock) throws IOException {
        this(path, clock, JsonlAuditTrail::appendAndForce);
    }

    JsonlAuditTrail(Path path, Clock clock, Appender appender) throws IOException {
        this.clock = Objects.requireNonNull(clock, "clock");
        this.appender = Objects.requireNonNull(appender, "appender");
        Objects.requireNonNull(path, "path");
        prepareFile(path);
        channel = FileChannel.open(path, StandardOpenOption.WRITE, StandardOpenOption.READ,
                LinkOption.NOFOLLOW_LINKS);
        FileLock acquired = null;
        try {
            acquired = channel.tryLock();
            if (acquired == null) throw new IOException("Audit trail already has a writer");
            try (var input = new BorrowedChannelInputStream(channel)) {
                if (AuditReader.scan(input, AuditQuery.all(1)).incompleteFinalLine()) {
                    throw new IOException("Archive incomplete audit tail before reopening writer");
                }
            }
            channel.position(channel.size());
            fileLock = acquired;
        } catch (IOException | RuntimeException e) {
            if (acquired != null) acquired.release();
            channel.close();
            if (e instanceof OverlappingFileLockException) {
                throw new IOException("Audit trail already has a writer");
            }
            throw e;
        }
    }

    /** Force ATTEMPTED before the host action; force SUCCEEDED/FAILED after its result. */
    @Override
    public synchronized AuditEvent record(AuditContext context, String action, String targetKind,
                                          String targetId, Environment environment,
                                          AuditEvent.Outcome outcome, List<String> changedFields) {
        AuditEvent event = new AuditEvent(1, UUID.randomUUID(), clock.instant(), context, action,
                targetKind, targetId, environment, outcome, changedFields);
        try {
            if (poisoned || !channel.isOpen()) throw new IOException("Audit writer unavailable");
            appender.append(channel, AuditJson.encode(event));
            return event;
        } catch (IOException e) {
            poisoned = true;
            // Do not attach causes: serializer/OS errors can contain caller data or file paths.
            throw new AuditPersistenceException(event);
        }
    }

    private static void appendAndForce(FileChannel channel, byte[] line) throws IOException {
        ByteBuffer buffer = ByteBuffer.allocate(line.length + 1).put(line).put((byte) '\n');
        buffer.flip();
        while (buffer.hasRemaining()) channel.write(buffer);
        channel.force(true);
    }

    /** Closing this view releases stream resources without closing the trail-owned channel. */
    private static final class BorrowedChannelInputStream extends InputStream {
        private final FileChannel borrowed;
        private BorrowedChannelInputStream(FileChannel borrowed) { this.borrowed = borrowed; }

        @Override
        public int read() throws IOException {
            ByteBuffer byteBuffer = ByteBuffer.allocate(1);
            return borrowed.read(byteBuffer) == -1 ? -1 : Byte.toUnsignedInt(byteBuffer.array()[0]);
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            return borrowed.read(ByteBuffer.wrap(bytes, offset, length));
        }
        // InputStream.close() is a no-op; JsonlAuditTrail.close() owns the channel lifetime.
    }

    private static void prepareFile(Path path) throws IOException {
        if (Files.isSymbolicLink(path)) throw new IOException("Audit path must not be a symbolic link");
        boolean posix = Files.getFileAttributeView(path.getParent() == null ? Path.of(".") : path.getParent(),
                PosixFileAttributeView.class) != null;
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (posix) Files.createFile(path, PosixFilePermissions.asFileAttribute(
                    PosixFilePermissions.fromString("rw-------")));
            else Files.createFile(path);
        }
        if (posix) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"));
        } else {
            AclFileAttributeView acl = Files.getFileAttributeView(path, AclFileAttributeView.class,
                    LinkOption.NOFOLLOW_LINKS);
            if (acl == null) throw new IOException("Owner-only file permissions are unsupported");
            acl.setAcl(List.of(AclEntry.newBuilder().setType(AclEntryType.ALLOW)
                    .setPrincipal(acl.getOwner()).setPermissions(EnumSet.allOf(AclEntryPermission.class)).build()));
        }
    }

    @Override
    public synchronized void close() throws IOException {
        try { if (fileLock.isValid()) fileLock.release(); }
        finally { channel.close(); }
    }
}
