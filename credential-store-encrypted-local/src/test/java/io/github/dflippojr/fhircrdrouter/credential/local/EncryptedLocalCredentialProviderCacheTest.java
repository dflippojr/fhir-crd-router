package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptedLocalCredentialProviderCacheTest {

    @Test
    void unchangedFileIsParsedOnce(@TempDir Path tempDir) {
        new EncryptedLocalCredentialProvider(tempDir).put("ref-1", "synthetic-value");
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);

        for (int i = 0; i < 50; i++) {
            assertEquals("synthetic-value", provider.resolve("ref-1").orElseThrow());
        }

        assertEquals(1, provider.parseCount());
    }

    @Test
    void putAndRemoveRefreshTheCacheWithoutReparsing(@TempDir Path tempDir) {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);

        provider.put("ref-1", "first");
        assertEquals("first", provider.resolve("ref-1").orElseThrow());
        provider.put("ref-1", "second");
        assertEquals("second", provider.resolve("ref-1").orElseThrow());
        provider.remove("ref-1");
        assertTrue(provider.resolve("ref-1").isEmpty());

        assertEquals(0, provider.parseCount());
    }

    @Test
    void externalSameLengthRewriteIsVisible(@TempDir Path tempDir) throws Exception {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-a", "value-a");
        provider.put("ref-b", "value-b");
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());

        // Another process swaps the two ciphertexts: same file length, different content.
        Path secrets = tempDir.resolve("secrets.properties");
        String original = Files.readString(secrets, StandardCharsets.ISO_8859_1);
        String swapped = original.replace("ref-a=", "ref-x=").replace("ref-b=", "ref-a=").replace("ref-x=", "ref-b=");
        assertNotEquals(original, swapped);
        assertEquals(original.length(), swapped.length());
        Files.writeString(secrets, swapped, StandardCharsets.ISO_8859_1);

        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
        assertEquals("value-a", provider.resolve("ref-b").orElseThrow());
        assertEquals(1, provider.parseCount());
    }

    @Test
    void deletedFileYieldsEmptyAndReappearanceIsVisible(@TempDir Path tempDir) throws Exception {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-1", "value");
        Path secrets = tempDir.resolve("secrets.properties");
        byte[] backup = Files.readAllBytes(secrets);

        Files.delete(secrets);
        assertTrue(provider.resolve("ref-1").isEmpty());

        Files.write(secrets, backup);
        assertEquals("value", provider.resolve("ref-1").orElseThrow());
    }

    @Test
    void cacheHoldsOnlyCiphertext(@TempDir Path tempDir) {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-1", "synthetic-plaintext-marker");
        provider.resolve("ref-1").orElseThrow();

        String cached = String.valueOf(provider.cachedEntries());
        assertTrue(cached.contains("ref-1"));
        assertFalse(cached.contains("synthetic-plaintext-marker"));
    }
}
