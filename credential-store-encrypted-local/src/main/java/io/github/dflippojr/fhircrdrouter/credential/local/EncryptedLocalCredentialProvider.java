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
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.nio.file.attribute.PosixFilePermission;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.LongSupplier;

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
    private static final SecureRandom IV_RANDOM = new SecureRandom();

    /** Default upper bound on how long a cached map is trusted on metadata alone. */
    public static final Duration DEFAULT_FULL_COMPARE_INTERVAL = Duration.ofSeconds(30);

    private final Path keyFile;
    private final Path secretsFile;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AuditSink auditSink;
    private final String storeId;
    private final long fullCompareIntervalNanos;
    private final LongSupplier nanoClock;
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
     * With a sink, first creation of {@code key.bin} is audited (ATTEMPTED before the file is
     * written, SUCCEEDED after) against the caller's context. The target is the fixed kind
     * {@code local-key-store} and an opaque digest of the store location, never a path or key bytes.
     * Loading an existing key is not an event. Without a sink behavior is unchanged.
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
        if (fullCompareInterval.isNegative()) {
            throw new IllegalArgumentException("fullCompareInterval must not be negative");
        }
        this.fullCompareIntervalNanos = fullCompareInterval.toNanos();
        this.nanoClock = Objects.requireNonNull(nanoClock, "nanoClock");
        this.keyFile = baseDir.resolve("key.bin");
        this.secretsFile = baseDir.resolve("secrets.properties");
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
            return Optional.of(decrypt(context, encoded));
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
            Map<String, String> entries = new HashMap<>(currentSnapshot().entries);
            entries.put(credentialRef, encrypt(context, secretValue));
            saveSecrets(entries);
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
            Map<String, String> entries = new HashMap<>(currentSnapshot().entries);
            if (entries.remove(credentialRef) != null) {
                saveSecrets(entries);
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private String encrypt(AuditContext context, String plaintext) {
        try {
            byte[] iv = new byte[GCM_IV_BYTES];
            IV_RANDOM.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(context), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return Base64.getEncoder().encodeToString(combined);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to encrypt credential", e);
        }
    }

    private String decrypt(AuditContext context, String encoded) {
        try {
            byte[] combined = Base64.getDecoder().decode(encoded);
            byte[] iv = new byte[GCM_IV_BYTES];
            byte[] ciphertext = new byte[combined.length - GCM_IV_BYTES];
            System.arraycopy(combined, 0, iv, 0, GCM_IV_BYTES);
            System.arraycopy(combined, GCM_IV_BYTES, ciphertext, 0, ciphertext.length);

            Cipher cipher = Cipher.getInstance(AES_GCM);
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(context), new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] plaintext = cipher.doFinal(ciphertext);
            return new String(plaintext, java.nio.charset.StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Failed to decrypt credential", e);
        }
    }

    private SecretKey getOrCreateKey(AuditContext context) {
        if (key != null) {
            return key;
        }
        synchronized (this) {
            if (key != null) {
                return key;
            }
            try {
                if (Files.exists(keyFile)) {
                    byte[] raw = Files.readAllBytes(keyFile);
                    key = new SecretKeySpec(raw, AES);
                } else {
                    audit(context, AuditEvent.Outcome.ATTEMPTED);
                    KeyGenerator keyGen = KeyGenerator.getInstance(AES);
                    keyGen.init(KEY_BITS);
                    SecretKey generated = keyGen.generateKey();
                    if (keyFile.getParent() != null) {
                        Files.createDirectories(keyFile.getParent());
                    }
                    Files.write(keyFile, generated.getEncoded());
                    tryRestrictToOwnerOnly(keyFile);
                    key = generated;
                    audit(context, AuditEvent.Outcome.SUCCEEDED);
                }
            } catch (IOException e) {
                throw new UncheckedIOException("Failed to load/create local credential key at " + keyFile, e);
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException("Failed to generate local credential key", e);
            }
            return key;
        }
    }

    private void audit(AuditContext context, AuditEvent.Outcome outcome) {
        if (auditSink != null) {
            auditSink.record(Objects.requireNonNull(context, "context"), "credential.key.create",
                    "local-key-store", storeId, null, outcome, List.of());
        }
    }

    private static void tryRestrictToOwnerOnly(Path path) {
        try {
            Set<PosixFilePermission> ownerOnly = PosixFilePermissions.fromString("rw-------");
            Files.setPosixFilePermissions(path, ownerOnly);
        } catch (UnsupportedOperationException | IOException ignored) {
            // Not a POSIX filesystem (e.g. plain Windows/NTFS without POSIX views) — best effort only.
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
        try {
            FileStamp stamp = readStamp();
            long now = nanoClock.getAsLong();
            Snapshot cached = snapshot;
            if (cached != null && stamp.equals(cached.stamp)
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
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            props.store(buffer, "fhir-crd-router encrypted credential references — values are AES-GCM ciphertext, not raw secrets");
            byte[] bytes = buffer.toByteArray();
            if (secretsFile.getParent() != null) {
                Files.createDirectories(secretsFile.getParent());
            }
            Files.write(secretsFile, bytes);
            tryRestrictToOwnerOnly(secretsFile);
            snapshot = new Snapshot(bytes, Map.copyOf(entries), readStamp(), nanoClock.getAsLong());
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing secrets file at " + secretsFile, e);
        }
    }
}
