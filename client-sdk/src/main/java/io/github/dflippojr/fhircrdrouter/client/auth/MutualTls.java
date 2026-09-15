package io.github.dflippojr.fhircrdrouter.client.auth;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Builds the client side of a mutual TLS connection from a PEM bundle: the
 * client certificate chain (leaf first) followed by its PKCS#8 private key,
 * as stored behind {@code ConnectionRecord#mtlsCredentialRef()}.
 */
public final class MutualTls {

    /** TLS 1.2 is the floor for PHI exchange under HRex; prefer 1.3 where the payer supports it. */
    static final String[] PROTOCOLS = {"TLSv1.3", "TLSv1.2"};

    private static final char[] IN_MEMORY_PASSWORD = new char[0];

    private MutualTls() { }

    /**
     * @param pemBundle client certificate chain plus private key
     * @param trustStore server certificates to trust, or {@code null} for the JVM's default trust store
     */
    public static SSLContext sslContext(String pemBundle, KeyStore trustStore) {
        List<X509Certificate> chain = PemKeys.readCertificates(pemBundle);
        if (chain.isEmpty()) {
            throw new IllegalArgumentException("mTLS credential must contain the client certificate chain");
        }
        PrivateKey key = PemKeys.readPrivateKey(pemBundle);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", key, IN_MEMORY_PASSWORD, chain.toArray(new X509Certificate[0]));

            KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            keyManagers.init(keyStore, IN_MEMORY_PASSWORD);
            TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagers.init(trustStore);

            SSLContext context = SSLContext.getInstance("TLS");
            context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), null);
            return context;
        } catch (GeneralSecurityException | java.io.IOException e) {
            throw new IllegalArgumentException("Could not build mTLS context: " + e.getMessage(), e);
        }
    }

    /** SSL parameters restricting connections to TLS 1.2+. */
    public static SSLParameters sslParameters() {
        SSLParameters parameters = new SSLParameters();
        parameters.setProtocols(PROTOCOLS);
        return parameters;
    }
}
