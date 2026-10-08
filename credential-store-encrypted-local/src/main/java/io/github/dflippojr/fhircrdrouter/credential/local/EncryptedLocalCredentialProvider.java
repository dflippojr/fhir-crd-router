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
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.locks.ReentrantReadWriteLock;

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
 */
public final class EncryptedLocalCredentialProvider implements ContextualCredentialProvider {

    private static final String AES = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;
    private static final int KEY_BITS = 256;
    private static final SecureRandom IV_RANDOM = new SecureRandom();

    private final Path keyFile;
    private final Path secretsFile;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AuditSink auditSink;
    private final String storeId;
    private volatile SecretKey key;

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
            Properties props = loadSecrets();
            String encoded = props.getProperty(credentialRef);
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
            Properties props = loadSecrets();
            props.setProperty(credentialRef, encrypt(context, secretValue));
            saveSecrets(props);
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
            Properties props = loadSecrets();
            if (props.remove(credentialRef) != null) {
                saveSecrets(props);
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

    private Properties loadSecrets() {
        Properties props = new Properties();
        if (Files.exists(secretsFile)) {
            try (var in = Files.newInputStream(secretsFile)) {
                props.load(in);
            } catch (IOException e) {
                throw new UncheckedIOException("Failed reading secrets file at " + secretsFile, e);
            }
        }
        return props;
    }

    private void saveSecrets(Properties props) {
        try {
            if (secretsFile.getParent() != null) {
                Files.createDirectories(secretsFile.getParent());
            }
            try (var out = Files.newOutputStream(secretsFile)) {
                props.store(out, "fhir-crd-router encrypted credential references — values are AES-GCM ciphertext, not raw secrets");
            }
            tryRestrictToOwnerOnly(secretsFile);
        } catch (IOException e) {
            throw new UncheckedIOException("Failed writing secrets file at " + secretsFile, e);
        }
    }
}
