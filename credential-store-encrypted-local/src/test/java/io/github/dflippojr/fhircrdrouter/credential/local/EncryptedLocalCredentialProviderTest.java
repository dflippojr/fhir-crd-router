package io.github.dflippojr.fhircrdrouter.credential.local;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EncryptedLocalCredentialProviderTest {

    @Test
    void roundTripsAndPersistsAcrossInstances(@TempDir Path tempDir) {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-1", "super-secret-value");

        assertEquals("super-secret-value", provider.resolve("ref-1").orElseThrow());

        // A fresh instance reusing the same on-disk key must decrypt the same value.
        EncryptedLocalCredentialProvider reopened = new EncryptedLocalCredentialProvider(tempDir);
        assertEquals("super-secret-value", reopened.resolve("ref-1").orElseThrow());
    }

    @Test
    void removeDeletesReference(@TempDir Path tempDir) {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        provider.put("ref-1", "value");
        provider.remove("ref-1");

        assertTrue(provider.resolve("ref-1").isEmpty());
    }

    @Test
    void unknownReferenceIsEmpty(@TempDir Path tempDir) {
        EncryptedLocalCredentialProvider provider = new EncryptedLocalCredentialProvider(tempDir);
        assertTrue(provider.resolve("nope").isEmpty());
    }
}
