package io.github.dflippojr.fhircrdrouter.client.auth;

import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PemKeysTest {

    private static final String PKCS8_HINT = "Private key must be PKCS#8 (BEGIN PRIVATE KEY); convert with "
            + "`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`";

    @TempDir
    Path dir;

    @Test
    void twoPkcs8BlocksAreRejected() {
        String pem = TestKeys.privateKeyPem(TestKeys.ec("secp384r1")) + TestKeys.privateKeyPem(TestKeys.ec("secp384r1"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PemKeys.readPrivateKey(pem));

        assertEquals("Expected exactly one PKCS#8 private key block, found 2", e.getMessage());
    }

    @Test
    void sec1EcKeyGetsTheConversionHint() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
                () -> PemKeys.readPrivateKey("-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----"));

        assertEquals(PKCS8_HINT, e.getMessage());
    }

    @Test
    void ed25519PrivateKeyIsRejected() {
        String pem = TestKeys.privateKeyPem(TestKeys.ed25519());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PemKeys.readPrivateKey(pem));

        assertEquals("Private key is neither RSA nor EC", e.getMessage());
    }

    @Test
    void corruptCertificateIsRejected() throws Exception {
        // Valid Base64 over truncated DER, so the failure comes from the certificate parser, not the decoder.
        byte[] der = TestKeys.selfSigned(dir, "pemkeys-leaf").certificate().getEncoded();
        String pem = PemKeys.toPem("CERTIFICATE", Arrays.copyOf(der, der.length / 2));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PemKeys.readCertificates(pem));

        assertEquals("Invalid certificate PEM", e.getMessage());
        assertInstanceOf(CertificateException.class, e.getCause());
    }

    @Test
    void publicKeyIsReadFromTheLeafCertificate() throws Exception {
        TestKeys.Identity leaf = TestKeys.selfSigned(dir, "pemkeys-leaf");
        TestKeys.Identity issuer = TestKeys.selfSigned(dir, "pemkeys-issuer");
        String chain = PemKeys.toPem("CERTIFICATE", leaf.certificate().getEncoded())
                + PemKeys.toPem("CERTIFICATE", issuer.certificate().getEncoded());

        assertEquals(leaf.certificate().getPublicKey(), PemKeys.readPublicKey(chain));
        assertNotEquals(issuer.certificate().getPublicKey(), PemKeys.readPublicKey(chain));
    }

    @Test
    void publicKeyNeedsAPublicKeyOrCertificateBlock() {
        String pem = TestKeys.privateKeyPem(TestKeys.ec("secp384r1"));

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(pem));

        assertEquals("No PUBLIC KEY or CERTIFICATE block found", e.getMessage());
    }

    @Test
    void ed25519PublicKeyIsRejected() {
        KeyPair ed = TestKeys.ed25519();
        String pem = PemKeys.toPem("PUBLIC KEY", ed.getPublic().getEncoded());

        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> PemKeys.readPublicKey(pem));

        assertEquals("Public key is neither RSA nor EC", e.getMessage());
    }
}
