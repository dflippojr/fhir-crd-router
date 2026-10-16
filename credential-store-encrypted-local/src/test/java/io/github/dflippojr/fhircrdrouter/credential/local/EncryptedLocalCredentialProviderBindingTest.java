package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Each entry is bound to its credentialRef, and unbound entries from earlier versions migrate (#113). */
class EncryptedLocalCredentialProviderBindingTest {

    @Test
    void newEntriesAreWrittenInTheBoundFormat(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref-a", "secret-a");

        String stored = entries(dir).getProperty("ref-a");
        assertTrue(stored.startsWith("v2:"), stored);
    }

    @Test
    void anEntryCopiedUnderAnotherReferenceFailsToDecrypt(@TempDir Path dir) throws Exception {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(dir);
        provider.put("ref-a", "secret-a");
        provider.put("ref-b", "");
        Properties properties = entries(dir);
        properties.setProperty("ref-a", properties.getProperty("ref-b"));
        store(dir, properties);

        EncryptedLocalCredentialProvider reopened = new EncryptedLocalCredentialProvider(dir);
        var e = assertThrows(IllegalStateException.class, () -> reopened.resolve("ref-a"));
        assertTrue(e.getMessage().contains("Failed to decrypt credential 'ref-a'"), e.getMessage());
        assertEquals("", reopened.resolve("ref-b").orElseThrow());
    }

    @Test
    void strippingThePrefixDoesNotSkipTheBinding(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref-a", "secret-a");
        Properties properties = entries(dir);
        properties.setProperty("ref-a", properties.getProperty("ref-a").substring("v2:".length()));
        store(dir, properties);

        var e = assertThrows(IllegalStateException.class, () -> new EncryptedLocalCredentialProvider(dir).resolve("ref-a"));
        assertTrue(e.getMessage().contains("Failed to decrypt credential 'ref-a'"), e.getMessage());
        assertFalse(e.getMessage().contains("secret-a"));
    }

    @Test
    void legacyEntriesResolveAndResolveDoesNotRewriteThem(@TempDir Path dir) throws Exception {
        Path secrets = legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));
        byte[] before = Files.readAllBytes(secrets);

        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(dir);
        assertEquals("secret-a", provider.resolve("ref-a").orElseThrow());
        assertEquals("secret-b", provider.resolve("ref-b").orElseThrow());

        assertArrayEquals(before, Files.readAllBytes(secrets));
    }

    @Test
    void putRewritesEveryLegacyEntryInTheBoundFormat(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));

        new EncryptedLocalCredentialProvider(dir).put("ref-c", "secret-c");

        assertAllBound(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b", "ref-c", "secret-c"));
    }

    @Test
    void putOverALegacyEntryReplacesItBound(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));

        new EncryptedLocalCredentialProvider(dir).put("ref-a", "secret-a2");

        assertAllBound(dir, Map.of("ref-a", "secret-a2", "ref-b", "secret-b"));
    }

    @Test
    void removeRewritesTheRemainingLegacyEntries(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));

        new EncryptedLocalCredentialProvider(dir).remove("ref-a");

        assertAllBound(dir, Map.of("ref-b", "secret-b"));
    }

    @Test
    void removeOfAnAbsentReferenceStillRewritesLegacyEntries(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a"));

        new EncryptedLocalCredentialProvider(dir).remove("absent");

        assertAllBound(dir, Map.of("ref-a", "secret-a"));
    }

    @Test
    void removeOfAnAbsentReferenceInABoundStoreWritesNothing(@TempDir Path dir) throws Exception {
        new EncryptedLocalCredentialProvider(dir).put("ref-a", "secret-a");
        Path secrets = dir.resolve("secrets.properties");
        byte[] before = Files.readAllBytes(secrets);

        new EncryptedLocalCredentialProvider(dir).remove("absent");

        assertArrayEquals(before, Files.readAllBytes(secrets));
    }

    @Test
    void anUndecryptableLegacyEntryIsLeftAsItIs(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a"));
        Properties properties = entries(dir);
        properties.setProperty("short", "AAAA");
        properties.setProperty("tampered", tamper(properties.getProperty("ref-a")));
        store(dir, properties);

        new EncryptedLocalCredentialProvider(dir).put("ref-c", "secret-c");

        Properties after = entries(dir);
        assertEquals("AAAA", after.getProperty("short"));
        assertEquals(properties.getProperty("tampered"), after.getProperty("tampered"));
        EncryptedLocalCredentialProvider reopened = new EncryptedLocalCredentialProvider(dir);
        assertEquals("secret-a", reopened.resolve("ref-a").orElseThrow());
        assertEquals("secret-c", reopened.resolve("ref-c").orElseThrow());
        assertThrows(IllegalStateException.class, () -> reopened.resolve("short"));
        assertThrows(IllegalStateException.class, () -> reopened.resolve("tampered"));
    }

    @Test
    void removeWithoutAKeyLeavesLegacyEntriesAndStillRemoves(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));
        Properties before = entries(dir);
        byte[] key = Files.readAllBytes(dir.resolve("key.bin"));
        Files.delete(dir.resolve("key.bin"));

        new EncryptedLocalCredentialProvider(dir).remove("ref-a");

        Properties after = entries(dir);
        assertFalse(after.containsKey("ref-a"));
        assertEquals(before.getProperty("ref-b"), after.getProperty("ref-b"));
        Files.write(dir.resolve("key.bin"), key);
        assertEquals("secret-b", new EncryptedLocalCredentialProvider(dir).resolve("ref-b").orElseThrow());
    }

    @Test
    void aMigratedEntryIsBoundToItsReference(@TempDir Path dir) throws Exception {
        legacyStore(dir, Map.of("ref-a", "secret-a", "ref-b", "secret-b"));
        new EncryptedLocalCredentialProvider(dir).put("ref-c", "secret-c");
        Properties properties = entries(dir);
        properties.setProperty("ref-a", properties.getProperty("ref-b"));
        store(dir, properties);

        assertThrows(IllegalStateException.class, () -> new EncryptedLocalCredentialProvider(dir).resolve("ref-a"));
    }

    private static void assertAllBound(Path dir, Map<String, String> expected) throws IOException {
        Properties properties = entries(dir);
        assertEquals(expected.keySet(), properties.stringPropertyNames());
        EncryptedLocalCredentialProvider reopened = new EncryptedLocalCredentialProvider(dir);
        for (Map.Entry<String, String> secret : expected.entrySet()) {
            assertTrue(properties.getProperty(secret.getKey()).startsWith("v2:"), secret.getKey());
            assertEquals(secret.getValue(), reopened.resolve(secret.getKey()).orElseThrow());
        }
    }

    /** A store as earlier versions wrote it: unprefixed entries encrypted without associated data. */
    private static Path legacyStore(Path dir, Map<String, String> secrets) throws Exception {
        // A put creates key.bin; its entry is then replaced by the legacy entries.
        new EncryptedLocalCredentialProvider(dir).put("seed", "seed");
        SecretKeySpec key = new SecretKeySpec(Files.readAllBytes(dir.resolve("key.bin")), "AES");
        Properties properties = new Properties();
        for (Map.Entry<String, String> secret : secrets.entrySet()) {
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ciphertext = cipher.doFinal(secret.getValue().getBytes(StandardCharsets.UTF_8));
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            properties.setProperty(secret.getKey(), Base64.getEncoder().encodeToString(combined));
        }
        return store(dir, properties);
    }

    private static String tamper(String encoded) {
        byte[] bytes = Base64.getDecoder().decode(encoded);
        bytes[bytes.length - 1] ^= 1;
        String tampered = Base64.getEncoder().encodeToString(bytes);
        assertNotEquals(encoded, tampered);
        return tampered;
    }

    private static Properties entries(Path dir) throws IOException {
        Properties properties = new Properties();
        try (InputStream in = Files.newInputStream(dir.resolve("secrets.properties"))) {
            properties.load(in);
        }
        return properties;
    }

    private static Path store(Path dir, Properties properties) throws IOException {
        Path secrets = dir.resolve("secrets.properties");
        try (OutputStream out = Files.newOutputStream(secrets)) {
            properties.store(out, null);
        }
        return secrets;
    }
}
