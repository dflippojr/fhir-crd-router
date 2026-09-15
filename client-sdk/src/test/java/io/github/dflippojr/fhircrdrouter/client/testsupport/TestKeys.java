package io.github.dflippojr.fhircrdrouter.client.testsupport;

import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Throwaway keys and certificates generated at test time, so no private key
 * material is ever committed. Certificates come from the JDK's {@code keytool}
 * because the JDK has no public API for creating X.509 certificates.
 */
public final class TestKeys {

    private static final String PASSWORD = "test-only";

    private TestKeys() { }

    public static KeyPair ec(String curve) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            generator.initialize(new ECGenParameterSpec(curve));
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public static String privateKeyPem(KeyPair pair) {
        return PemKeys.toPem("PRIVATE KEY", pair.getPrivate().getEncoded());
    }

    /** A self-signed P-384 certificate valid for localhost and 127.0.0.1, with its private key. */
    public static Identity selfSigned(Path dir, String commonName) {
        Path store = dir.resolve(commonName + ".p12");
        String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
        run(keytool, "-genkeypair", "-alias", "id", "-keyalg", "EC", "-groupname", "secp384r1",
                "-sigalg", "SHA384withECDSA", "-dname", "CN=" + commonName,
                "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-validity", "2",
                "-storetype", "PKCS12", "-keystore", store.toString(),
                "-storepass", PASSWORD, "-keypass", PASSWORD);
        try (InputStream in = Files.newInputStream(store)) {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(in, PASSWORD.toCharArray());
            PrivateKey key = (PrivateKey) keyStore.getKey("id", PASSWORD.toCharArray());
            X509Certificate certificate = (X509Certificate) keyStore.getCertificate("id");
            return new Identity(key, certificate);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public record Identity(PrivateKey key, X509Certificate certificate) {

        /** Certificate chain followed by the PKCS#8 key: the mTLS credential format. */
        public String pemBundle() {
            try {
                return PemKeys.toPem("CERTIFICATE", certificate.getEncoded())
                        + PemKeys.toPem("PRIVATE KEY", key.getEncoded());
            } catch (GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        /** A key store holding this identity's private key, for the server side of a test. */
        public KeyStore keyStore() {
            return store(true);
        }

        /** A trust store containing only this identity's certificate. */
        public KeyStore trustStore() {
            return store(false);
        }

        private KeyStore store(boolean withKey) {
            try {
                KeyStore store = KeyStore.getInstance("PKCS12");
                store.load(null, null);
                if (withKey) {
                    store.setKeyEntry("id", key, PASSWORD.toCharArray(), new X509Certificate[] {certificate});
                } else {
                    store.setCertificateEntry("id", certificate);
                }
                return store;
            } catch (IOException | GeneralSecurityException e) {
                throw new IllegalStateException(e);
            }
        }

        public static char[] password() {
            return PASSWORD.toCharArray();
        }
    }

    private static void run(String... command) {
        try {
            Process process = new ProcessBuilder(List.of(command)).redirectErrorStream(true).start();
            String output = new String(process.getInputStream().readAllBytes());
            if (!process.waitFor(60, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw new IllegalStateException("keytool failed: " + output);
            }
        } catch (IOException e) {
            throw new IllegalStateException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
