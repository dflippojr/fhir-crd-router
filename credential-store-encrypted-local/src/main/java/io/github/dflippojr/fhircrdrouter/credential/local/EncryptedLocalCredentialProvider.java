package io.github.dflippojr.fhircrdrouter.credential.local;

import io.github.dflippojr.fhircrdrouter.core.audit.AuditContext;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditEvent;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditSink;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditTargets;
import io.github.dflippojr.fhircrdrouter.core.audit.ContextualCredentialProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;
import java.util.function.UnaryOperator;

/**
 * Default, dependency-free {@link CredentialProvider}: each secret is
 * AES-256-GCM encrypted with a key generated on first use and stored
 * alongside the secrets file. This is a "good enough for a solo personal
 * project on your own machine" default, not a Vault/KMS replacement — swap
 * in a real secrets manager adapter for anything beyond that.
 *
 * <p>Directory layout under the given base directory:
 * <ul>
 *   <li>{@code key.bin} — raw 256-bit AES key (mode 600 where POSIX permissions apply)</li>
 *   <li>{@code secrets.properties} — {@code credentialRef -> base64(iv || ciphertext)}</li>
 * </ul>
 *
 * <p>Both files are created owner-only (mode 600 where POSIX permissions apply) and never
 * rewritten in place. Each write of {@code secrets.properties} goes to a temporary file
 * ({@code secrets.properties.*.tmp}) in the same directory, is forced to disk and is then moved
 * over the target, so a reader sees either the old or the new complete file and a crash or full
 * disk leaves the previous content intact. {@code key.bin} is only created by {@code put} on a
 * store with no entries: the new key is written to a temporary file and then linked into place
 * without ever replacing an existing file, so when instances race on first use exactly one key is
 * published and every instance uses it. {@code resolve} never creates a key.
 *
 * <p>{@code put} and {@code remove} are safe across instances and processes on one directory:
 * each holds an exclusive OS file lock on {@code secrets.lock} (a sidecar file that is created
 * empty and never deleted) while it re-reads {@code secrets.properties}, applies its change and
 * moves the new file into place, so concurrent writers serialize and every write survives.
 * Instances in one JVM also share a mutex per directory, because the JVM refuses to hand out two
 * overlapping file locks. A writer waits for the lock without a timeout. {@code resolve} takes no
 * file lock; the atomic replace already gives it a complete file.
 *
 * <p>Damaged material fails with an {@link IllegalStateException} that names the problem and
 * never contains ciphertext or plaintext: a missing {@code key.bin} next to stored entries (a
 * {@code put} then writes nothing either, so secrets under two different keys never mix), a
 * {@code key.bin} that is not exactly 256 bits, a {@code secrets.properties} that is not a valid
 * properties file (a {@code put} then writes nothing), or an entry that is not valid
 * {@code base64(iv || ciphertext || tag)}.
 *
 * <p>The parsed ciphertext map is cached together with the raw file bytes and file metadata
 * (last-modified time, size and, where the filesystem has one, file key) it came from. Each
 * {@code resolve} compares only the metadata; when it differs, or when the cache has gone
 * unverified for the full-compare interval (default {@link #DEFAULT_FULL_COMPARE_INTERVAL}), the
 * file bytes are re-read and the map is re-parsed only if they differ. A same-size external
 * rewrite that keeps the old last-modified time (coarse timestamp granularity, a restore that
 * preserves times) is therefore picked up within at most that interval. Decryption still happens
 * on every call: plaintext is never cached.
 */
public final class EncryptedLocalCredentialProvider implements ContextualCredentialProvider {

    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;
    private static final int KEY_BITS = 256;
    private static final int KEY_BYTES = KEY_BITS / 8;
    private static final String OWNER_ONLY = "rw-------";
    private static final int REPLACE_ATTEMPTS = 25;
    /** One mutex per lock file for this JVM; {@link FileChannel#lock()} fails instead of waiting inside one JVM. */
    private static final Map<Path, ReentrantLock> DIRECTORY_LOCKS = new ConcurrentHashMap<>();
    private static final SecureRandom IV_RANDOM = new SecureRandom();

    /** Default upper bound on how long a cached map is trusted on metadata alone. */
    public static final Duration DEFAULT_FULL_COMPARE_INTERVAL = Duration.ofSeconds(30);

    private final Path keyFile;
    private final Path secretsFile;
    private final Path lockFile;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AuditSink auditSink;
    private final String storeId;
    private final long fullCompareIntervalNanos;
    private final LongSupplier nanoClock;
    private final UnaryOperator<OutputStream> outputWrapper;
    private volatile SecretKey key;
    private volatile Snapshot snapshot;
    private final AtomicInteger parseCount = new AtomicInteger();

    /** File metadata that, when unchanged, lets {@code resolve} skip reading the file. */
    private record FileStamp(FileTime lastModified, long size, Object fileKey) {
    }

    /**
     * Ciphertext entries parsed from the raw file content they came from. {@link #ABSENT} stands
     * for a missing file. Plaintext is never held here.
     */
    private static final class Snapshot {
        static final Snapshot ABSENT = new Snapshot(null, Map.of(), null, 0L);

        private final byte[] bytes;
        final Map<String, String> entries;
        final FileStamp stamp;
        final long verifiedAtNanos;

        Snapshot(byte[] bytes, Map<String, String> entries, FileStamp stamp, long verifiedAtNanos) {
            this.bytes = bytes;
            this.entries = entries;
            this.stamp = stamp;
            this.verifiedAtNanos = verifiedAtNanos;
        }

        boolean matches(byte[] content) {
            return Arrays.equals(bytes, content);
        }
    }

    public EncryptedLocalCredentialProvider(Path baseDir) {
        this(baseDir, null);
    }

    /**
     * With a sink, creation of {@code key.bin} is audited against the caller's context: ATTEMPTED
     * before the key is generated, then SUCCEEDED once this instance has published it, or FAILED
     * when the write failed or another instance or process published {@code key.bin} first (that
     * key is then loaded and used). The target is the fixed kind {@code local-key-store} and an
     * opaque digest of the store location, never a path or key bytes. Loading an existing key is
     * not an event. Without a sink behavior is unchanged.
     */
    public EncryptedLocalCredentialProvider(Path baseDir, AuditSink auditSink) {
        this(baseDir, auditSink, DEFAULT_FULL_COMPARE_INTERVAL);
    }

    /**
     * As {@link #EncryptedLocalCredentialProvider(Path, AuditSink)}, with the longest time a cached
     * map is trusted on file metadata alone before the file bytes are compared again.
     * {@link Duration#ZERO} compares the bytes on every {@code resolve}.
     */
    public EncryptedLocalCredentialProvider(Path baseDir, AuditSink auditSink, Duration fullCompareInterval) {
        this(baseDir, auditSink, fullCompareInterval, System::nanoTime);
    }

    EncryptedLocalCredentialProvider(Path baseDir, AuditSink auditSink, Duration fullCompareInterval,
                                     LongSupplier nanoClock) {
        this(baseDir, auditSink, fullCompareInterval, nanoClock, UnaryOperator.identity());
    }

    // Visible for tests, which wrap the temporary-file stream to make a write fail midway.
    EncryptedLocalCredentialProvider(Path baseDir, AuditSink auditSink, Duration fullCompareInterval,
                                     LongSupplier nanoClock, UnaryOperator<OutputStream> outputWrapper) {
        if (fullCompareInterval.isNegative()) {
            throw new IllegalArgumentException("fullCompareInterval must not be negative");
        }
        this.fullCompareIntervalNanos = fullCompareInterval.toNanos();
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
        this.outputWrapper = Objects.requireNonNull(outputWrapper, "outputWrapper");
        this.keyFile = baseDir.resolve("key.bin");
        this.secretsFile = baseDir.resolve("secrets.properties");
        this.lockFile = baseDir.resolve("secrets.lock");
        this.auditSink = auditSink;
        this.storeId = "enc-local-" + AuditTargets.digest(baseDir.toAbsolutePath().normalize().toString(), 16);
    }

    @Override
    public Optional<String> resolve(String credentialRef) {
        return resolve(AuditContext.unknown(), credentialRef);
    }

    @Override
    public Optional<String> resolve(AuditContext context, String credentialRef) {
        lock.readLock().lock();
        try {
            String encoded = currentSnapshot().entries.get(credentialRef);
            if (encoded == null) {
                return Optional.empty();
            }
            return Optional.of(decrypt(credentialRef, encoded));
        } finally {
            lock.readLock().unlock();
        }
    }

    @Override
    public void put(String credentialRef, String secretValue) {
        put(AuditContext.unknown(), credentialRef, secretValue);
    }

    @Override
    public void put(AuditContext context, String credentialRef, String secretValue) {
        lock.writeLock().lock();
        try {
            withStoreLock(() -> {
                Map<String, String> entries = new HashMap<>(freshSnapshot().entries);
                SecretKey writeKey = keyForPut(context, entries.isEmpty());
                entries.put(credentialRef, encrypt(writeKey, secretValue));
                saveSecrets(entries);
            });
        } finally {
            lock.writeLock().unlock();
        }
    }

    @Override
    public void remove(String credentialRef) {
        remove(AuditContext.unknown(), credentialRef);
    }

    @Override
    public void remove(AuditContext context, String credentialRef) {
        lock.writeLock().lock();
        try {
            if (Files.notExists(secretsFile)) {
                return;
            }
            withStoreLock(() -> {
                Map<String, String> entries = new HashMap<>(freshSnapshot().entries);
                if (entries.remove(credentialRef) != null) {
                    saveSecrets(entries);
                }
            });
        } finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * Runs {@code body} while this thread alone may change the store, across instances, threads and
     * processes on this directory: first the per-directory mutex, then the OS lock, which closing
     * the lock channel releases.
     */
    private void withStoreLock(Runnable body) {
        ReentrantLock mutex = DIRECTORY_LOCKS.computeIfAbsent(lockFile.toAbsolutePath().normalize(),
                ignored -> new ReentrantLock());
        mutex.lock();
        try {
            FileChannel channel = null;
            try {
                Path dir = lockFile.toAbsolutePath().getParent();
                Files.createDirectories(dir);
                channel = openLockChannel(dir);
                acquire(channel);
                body.run();
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to lock the credential store at " + lockFile, e);
            } finally {
                closeQuietly(channel);
            }
        } finally {
            mutex.unlock();
        }
    }

    private void acquire(FileChannel channel) throws IOException {
        try {
            channel.lock();
        } catch (OverlappingFileLockException e) {
            throw new IllegalStateException("The credential store at " + lockFile
                    + " is already being written by this thread; put and remove must not be called from inside a put or remove", e);
        }
    }

    private FileChannel openLockChannel(Path dir) throws IOException {
        Set<StandardOpenOption> options = Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE);
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return FileChannel.open(lockFile, options,
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(OWNER_ONLY)));
        }
        return FileChannel.open(lockFile, options);
    }

    private static void closeQuietly(FileChannel channel) {
        if (channel == null) {
            return;
        }
        try {
            channel.close();
        } catch (IOException ignored) {
            // Best effort; the original failure is what matters.
        }
    }

    private static String encrypt(SecretKey secretKey, String plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            IV_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt credential", e);
        }
    }

    private String decrypt(String credentialRef, String encoded) {
        byte[] combined;
        try {
            combined = Base64.getDecoder().decode(encoded);
        } catch (IllegalArgumentException e) {
            // The decoder's message quotes the offending character, so it is not chained.
            throw corruptEntry(credentialRef);
        }
        if (combined.length < GCM_IV_BYTES + GCM_TAG_BITS / 8) {
            throw corruptEntry(credentialRef);
        }
        SecretKey secretKey = loadKey();
        try {
            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_TAG_BITS, combined, 0, GCM_IV_BYTES));
            byte[] plaintext = cipher.doFinal(combined, GCM_IV_BYTES, combined.length - GCM_IV_BYTES);
            return new String(plaintext, StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt credential '" + credentialRef + "'", e);
        }
    }

    private IllegalStateException corruptEntry(String credentialRef) {
        return new IllegalStateException("Corrupt credential entry '" + credentialRef + "' in " + secretsFile
                + ": not base64(iv || ciphertext || tag)");
    }

    /** The key for decrypting; never creates one. */
    private SecretKey loadKey() {
        SecretKey cached = key;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (key == null) {
                key = readKeyFile().orElseThrow(this::missingKey);
            }
            return key;
        }
    }

    /**
     * The key for encrypting a new entry. Creates {@code key.bin} only when it is absent and the
     * store has no entries; entries without a key mean the key was lost, and a new one would make
     * a later restore of the original key strand everything written in between.
     */
    private SecretKey keyForPut(AuditContext context, boolean storeEmpty) {
        SecretKey cached = key;
        if (cached != null) {
            return cached;
        }
        synchronized (this) {
            if (key == null) {
                Optional<SecretKey> existing = readKeyFile();
                if (existing.isPresent()) {
                    key = existing.get();
                } else if (storeEmpty) {
                    key = createKey(context);
                } else {
                    throw missingKey();
                }
            }
            return key;
        }
    }

    private IllegalStateException missingKey() {
        return new IllegalStateException("Local credential key is missing at " + keyFile + " but " + secretsFile
                + " has entries; restore the key.bin that was used to write them");
    }

    /** Reads and validates {@code key.bin}; empty when the file does not exist. */
    private Optional<SecretKey> readKeyFile() {
        byte[] raw;
        try {
            raw = Files.readAllBytes(keyFile);
        } catch (NoSuchFileException e) {
            return Optional.empty();
        } catch (IOException e) {
            throw new UncheckedIOException("Failed to load local credential key at " + keyFile, e);
        }
        try {
            if (raw.length != KEY_BYTES) {
                throw new IllegalStateException("Local credential key at " + keyFile + " is not a 256-bit AES key ("
                        + raw.length + " bytes instead of " + KEY_BYTES + ")");
            }
            return Optional.of(new SecretKeySpec(raw, AES));
        } finally {
            Arrays.fill(raw, (byte) 0);
        }
    }

    /**
     * Generates a key and publishes it as {@code key.bin} unless that file appeared meanwhile, in
     * which case the published key wins and is returned instead.
     */
    private SecretKey createKey(AuditContext context) {
        audit(context, AuditEvent.Outcome.ATTEMPTED);
        Path tmp = null;
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            keyGen.init(KEY_BITS);
            SecretKey generated = keyGen.generateKey();
            Path dir = keyFile.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            tmp = createOwnerOnlyTempFile(dir, keyFile);
            writeDurably(tmp, generated.getEncoded());
            if (publishWithoutReplacing(tmp)) {
                audit(context, AuditEvent.Outcome.SUCCEEDED);
                return generated;
            }
            // Another instance or process published key.bin first; this key was never used.
            audit(context, AuditEvent.Outcome.FAILED);
            return readKeyFile().orElseThrow(() -> new IllegalStateException(
                    "Local credential key at " + keyFile + " disappeared while it was being created"));
        } catch (IOException e) {
            UncheckedIOException failure = new UncheckedIOException(
                    "Failed to create local credential key at " + keyFile, e);
            auditFailure(context, failure);
            throw failure;
        } catch (GeneralSecurityException e) {
            IllegalStateException failure = new IllegalStateException("Failed to generate local credential key", e);
            auditFailure(context, failure);
            throw failure;
        } finally {
            deleteQuietly(tmp);
        }
    }

    /**
     * Makes {@code tmp} visible as {@code key.bin} in one step, failing rather than replacing an
     * existing file. Returns false when {@code key.bin} already exists.
     */
    private boolean publishWithoutReplacing(Path tmp) throws IOException {
        try {
            Files.createLink(keyFile, tmp);
            return true;
        } catch (FileAlreadyExistsException e) {
            return false;
        } catch (UnsupportedOperationException | FileSystemException e) {
            // No hard links on this filesystem; a move without REPLACE_EXISTING also refuses to overwrite.
            try {
                Files.move(tmp, keyFile);
                return true;
            } catch (FileAlreadyExistsException exists) {
                return false;
            }
        }
    }

    private void audit(AuditContext context, AuditEvent.Outcome outcome) {
        if (auditSink != null) {
            auditSink.record(Objects.requireNonNull(context, "context"), "credential.key.create",
                    "local-key-store", storeId, null, outcome, List.of());
        }
    }

    private void auditFailure(AuditContext context, RuntimeException failure) {
        try {
            audit(context, AuditEvent.Outcome.FAILED);
        } catch (RuntimeException auditFailure) {
            failure.addSuppressed(auditFailure);
        }
    }

    /** Number of times {@code secrets.properties} has been parsed; for tests. */
    int parseCount() {
        return parseCount.get();
    }

    /** The cached ciphertext entries, or an empty map before the first read; for tests. */
    Map<String, String> cachedEntries() {
        Snapshot cached = snapshot;
        return cached == null ? Map.of() : cached.entries;
    }

    /**
     * Returns the cached snapshot when the file metadata is unchanged and the cache was verified
     * within the full-compare interval. Otherwise reads the bytes and re-parses only if they differ.
     * The stamp is read before the bytes, so a write landing in between changes the stamp and is
     * re-checked on the next call. Concurrent readers may both refresh; each publishes an
     * immutable, equivalent snapshot, so the race is harmless.
     */
    private Snapshot currentSnapshot() {
        return loadSnapshot(false);
    }

    /**
     * The file's current content, compared byte for byte. A writer uses this under the file lock:
     * another process may have replaced the file since the cache was verified, within the same
     * timestamp tick and size, so metadata alone cannot be trusted before a read-modify-write.
     */
    private Snapshot freshSnapshot() {
        return loadSnapshot(true);
    }

    private Snapshot loadSnapshot(boolean forceCompare) {
        try {
            FileStamp stamp = readStamp();
            long now = nanoClock.getAsLong();
            Snapshot cached = snapshot;
            if (!forceCompare && cached != null && stamp.equals(cached.stamp)
                    && now - cached.verifiedAtNanos < fullCompareIntervalNanos) {
                return cached;
            }
            byte[] bytes = Files.readAllBytes(secretsFile);
            Map<String, String> entries = cached != null && cached.matches(bytes) ? cached.entries : parse(bytes);
            Snapshot fresh = new Snapshot(bytes, entries, stamp, now);
            snapshot = fresh;
            return fresh;
        } catch (NoSuchFileException e) {
            snapshot = Snapshot.ABSENT;
            return Snapshot.ABSENT;
        } catch (IOException e) {
            throw new UncheckedIOException("Failed reading secrets file at " + secretsFile, e);
        }
    }

    private FileStamp readStamp() throws IOException {
        BasicFileAttributes attributes = Files.readAttributes(secretsFile, BasicFileAttributes.class);
        return new FileStamp(attributes.lastModifiedTime(), attributes.size(), attributes.fileKey());
    }

    private Map<String, String> parse(byte[] bytes) {
        parseCount.incrementAndGet();
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            throw new UncheckedIOException("Failed parsing secrets file at " + secretsFile, e);
        } catch (IllegalArgumentException e) {
            // A malformed unicode escape. No cause: a future JDK's message might quote file content.
            throw new IllegalStateException("Secrets file at " + secretsFile + " is not a valid properties file");
        }
        Map<String, String> entries = new HashMap<>();
        for (String name : props.stringPropertyNames()) {
            entries.put(name, props.getProperty(name));
        }
        return Map.copyOf(entries);
    }

    private void saveSecrets(Map<String, String> entries) {
        Properties props = new Properties();
        props.putAll(entries);
        Path tmp = null;
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            props.store(buffer, "fhir-crd-router encrypted credential references — values are AES-GCM ciphertext, not raw secrets");
            byte[] bytes = buffer.toByteArray();
            Path dir = secretsFile.toAbsolutePath().getParent();
            Files.createDirectories(dir);
            tmp = createOwnerOnlyTempFile(dir, secretsFile);
            writeDurably(tmp, bytes);
            replace(tmp, secretsFile);
            tmp = null;
            snapshot = new Snapshot(bytes, Map.copyOf(entries), readStamp(), nanoClock.getAsLong());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing secrets file at " + secretsFile, e);
        } finally {
            deleteQuietly(tmp);
        }
    }

    /** A {@code <target>.*.tmp} file next to the target, owner-only from creation where POSIX applies. */
    private static Path createOwnerOnlyTempFile(Path dir, Path target) throws IOException {
        String prefix = target.getFileName() + ".";
        if (dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
            return Files.createTempFile(dir, prefix, ".tmp",
                    PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(OWNER_ONLY)));
        }
        return Files.createTempFile(dir, prefix, ".tmp");
    }

    private void writeDurably(Path file, byte[] bytes) throws IOException {
        try (FileChannel channel = FileChannel.open(file, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);
             OutputStream out = outputWrapper.apply(Channels.newOutputStream(channel))) {
            out.write(bytes);
            out.flush();
            channel.force(true);
        }
    }

    /**
     * Moves {@code tmp} over {@code target}. Windows refuses to replace a file that another handle
     * has open, and a reader holds it only for one read, so a refused replace is retried briefly.
     */
    private static void replace(Path tmp, Path target) throws IOException {
        for (int attempt = 1; ; attempt++) {
            try {
                moveOver(tmp, target);
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

    private static void moveOver(Path tmp, Path target) throws IOException {
        try {
            Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void deleteQuietly(Path tmp) {
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
