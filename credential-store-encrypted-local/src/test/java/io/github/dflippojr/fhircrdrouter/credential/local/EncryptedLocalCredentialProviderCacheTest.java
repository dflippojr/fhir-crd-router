package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
        Path secrets = tempDir.resolve("secrets.properties");
        byte[] earlier = putTwice(provider, secrets);

        FileTime before = Files.getLastModifiedTime(secrets);
        rewriteSameLength(secrets, earlier);
        Files.setLastModifiedTime(secrets, FileTime.fromMillis(before.toMillis() + 10_000));

        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());
        assertEquals(1, provider.parseCount());
    }

    @Test
    void sameLengthRewriteKeepingMtimeIsVisibleAfterFullCompareInterval(@TempDir Path tempDir) throws Exception {
        AtomicLong clock = new AtomicLong();
        EncryptedLocalCredentialProvider provider =
                new EncryptedLocalCredentialProvider(tempDir, null, Duration.ofSeconds(30), clock::get);
        Path secrets = tempDir.resolve("secrets.properties");
        byte[] earlier = putTwice(provider, secrets);

        FileTime before = Files.getLastModifiedTime(secrets);
        rewriteSameLength(secrets, earlier);
        Files.setLastModifiedTime(secrets, before);

        clock.addAndGet(Duration.ofSeconds(29).toNanos());
        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
        assertEquals(0, provider.parseCount());

        clock.addAndGet(Duration.ofSeconds(1).toNanos());
        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());
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
        Path secrets = tempDir.resolve("secrets.properties");
        byte[] earlier = putTwice(provider, secrets);

        FileTime before = Files.getLastModifiedTime(secrets);
        rewriteSameLength(secrets, earlier);
        Files.setLastModifiedTime(secrets, before);

        assertEquals("value-a", provider.resolve("ref-a").orElseThrow());
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

    /**
     * Puts ref-a as value-a, then as value-b, and returns the file bytes from the first put. Entries
     * are bound to their reference, so an earlier copy of the file, not a swap of two entries, is
     * what gives same-length content that resolves to another value.
     */
    private static byte[] putTwice(EncryptedLocalCredentialProvider provider, Path secrets) throws Exception {
        provider.put("ref-a", "value-a");
        byte[] earlier = Files.readAllBytes(secrets);
        provider.put("ref-a", "value-b");
        assertEquals("value-b", provider.resolve("ref-a").orElseThrow());
        return earlier;
    }

    /** Overwrites the file in place with other content of the same length. */
    private static void rewriteSameLength(Path secrets, byte[] content) throws Exception {
        byte[] current = Files.readAllBytes(secrets);
        assertFalse(Arrays.equals(current, content));
        assertEquals(current.length, content.length);
        Files.write(secrets, content);
    }
}
