package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
    void externalSameLengthRewriteWithNewMtimeIsVisible(@TempDir Path tempDir) throws Exception {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-a", "value-a");
        provider.put("ref-b", "value-b");
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());

        Path secrets = tempDir.resolve("secrets.properties");
        FileTime before = Files.getLastModifiedTime(secrets);
        swapCiphertexts(secrets);
        Files.setLastModifiedTime(secrets, FileTime.fromMillis(before.toMillis() + 10_000));

        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
        assertEquals("value-a", provider.resolve("ref-b").orElseThrow());
        assertEquals(1, provider.parseCount());
    }

    @Test
    void sameLengthRewriteKeepingMtimeIsVisibleAfterFullCompareInterval(@TempDir Path tempDir) throws Exception {
        AtomicLong clock = new AtomicLong();
        EncryptedLocalCredentialProvider provider =
                new EncryptedLocalCredentialProvider(tempDir, null, Duration.ofSeconds(30), clock::get);
        provider.put("ref-a", "value-a");
        provider.put("ref-b", "value-b");
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());

        Path secrets = tempDir.resolve("secrets.properties");
        FileTime before = Files.getLastModifiedTime(secrets);
        swapCiphertexts(secrets);
        Files.setLastModifiedTime(secrets, before);

        clock.addAndGet(Duration.ofSeconds(29).toNanos());
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());
        assertEquals(0, provider.parseCount());

        clock.addAndGet(Duration.ofSeconds(1).toNanos());
        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
        assertEquals(1, provider.parseCount());
    }

    @Test
    void periodicCompareOfUnchangedFileDoesNotReparse(@TempDir Path tempDir) {
        AtomicLong clock = new AtomicLong();
        EncryptedLocalCredentialProvider provider =
                new EncryptedLocalCredentialProvider(tempDir, null, Duration.ofSeconds(30), clock::get);
        provider.put("ref-1", "value");

        for (int i = 0; i < 5; i++) {
            clock.addAndGet(Duration.ofMinutes(1).toNanos());
            assertEquals("value", provider.resolve("ref-1").orElseThrow());
        }

        assertEquals(0, provider.parseCount());
    }

    @Test
    void zeroIntervalComparesBytesEveryTime(@TempDir Path tempDir) throws Exception {
        EncryptedLocalCredentialProvider provider =
                new EncryptedLocalCredentialProvider(tempDir, null, Duration.ZERO);
        provider.put("ref-a", "value-a");
        provider.put("ref-b", "value-b");
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());

        Path secrets = tempDir.resolve("secrets.properties");
        FileTime before = Files.getLastModifiedTime(secrets);
        swapCiphertexts(secrets);
        Files.setLastModifiedTime(secrets, before);

        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
    }

    @Test
    void negativeIntervalIsRejected(@TempDir Path tempDir) {
        Duration negative = Duration.ofSeconds(-1);
        assertThrows(IllegalArgumentException.class,
                () -> new EncryptedLocalCredentialProvider(tempDir, null, negative));
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

    /** Swaps the two entries' ciphertexts in place: same file length, different content. */
    private static void swapCiphertexts(Path secrets) throws Exception {
        String original = Files.readString(secrets, StandardCharsets.ISO_8859_1);
        String swapped = original.replace("ref-a=", "ref-x=").replace("ref-b=", "ref-a=").replace("ref-x=", "ref-b=");
        assertNotEquals(original, swapped);
        assertEquals(original.length(), swapped.length());
        Files.writeString(secrets, swapped, StandardCharsets.ISO_8859_1);
    }
}
