package io.github.dflippojr.fhircrdrouter.client.auth;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads keys and certificates from PEM text using only the JDK.
 *
 * <p>Private keys must be unencrypted PKCS#8 ({@code -----BEGIN PRIVATE KEY-----}).
 * Convert PKCS#1 or SEC1 keys with
 * {@code openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem}.
 */
public final class PemKeys {

    private static final Pattern BLOCK = Pattern.compile(
            "-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \\1-----", Pattern.DOTALL);

    private PemKeys() { }

    /** Reads the single PKCS#8 private key (RSA or EC) in {@code pem}. */
    public static PrivateKey readPrivateKey(String pem) {
        List<byte[]> keys = blocks(pem, "PRIVATE KEY");
        if (keys.size() != 1) {
            if (!blocks(pem, "RSA PRIVATE KEY").isEmpty() || !blocks(pem, "EC PRIVATE KEY").isEmpty()) {
                throw new IllegalArgumentException("Private key must be PKCS#8 (BEGIN PRIVATE KEY); convert with "
                        + "`openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`");
            }
            throw new IllegalArgumentException("Expected exactly one PKCS#8 private key block, found " + keys.size());
        }
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keys.get(0));
        for (String algorithm : List.of("RSA", "EC")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePrivate(spec);
            } catch (GeneralSecurityException ignored) {
                // try the next algorithm
            }
        }
        throw new IllegalArgumentException("Private key is neither RSA nor EC");
    }

    /** Reads every certificate in {@code pem}, in order (leaf first for a chain). */
    public static List<X509Certificate> readCertificates(String pem) {
        try {
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            List<X509Certificate> certificates = new ArrayList<>();
            for (byte[] der : blocks(pem, "CERTIFICATE")) {
                certificates.add((X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
            }
            return certificates;
        } catch (CertificateException e) {
            throw new IllegalArgumentException("Invalid certificate PEM", e);
        }
    }

    /** Reads a {@code PUBLIC KEY} block, or the public key of the first {@code CERTIFICATE}. */
    public static PublicKey readPublicKey(String pem) {
        List<byte[]> keys = blocks(pem, "PUBLIC KEY");
        if (keys.isEmpty()) {
            List<X509Certificate> certificates = readCertificates(pem);
            if (certificates.isEmpty()) {
                throw new IllegalArgumentException("No PUBLIC KEY or CERTIFICATE block found");
            }
            return certificates.get(0).getPublicKey();
        }
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keys.get(0));
        for (String algorithm : List.of("RSA", "EC")) {
            try {
                return KeyFactory.getInstance(algorithm).generatePublic(spec);
            } catch (GeneralSecurityException ignored) {
                // try the next algorithm
            }
        }
        throw new IllegalArgumentException("Public key is neither RSA nor EC");
    }

    /** Encodes DER bytes as a PEM block, e.g. {@code toPem("PRIVATE KEY", key.getEncoded())}. */
    public static String toPem(String type, byte[] der) {
        String body = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(der);
        return "-----BEGIN " + type + "-----\n" + body + "\n-----END " + type + "-----\n";
    }

    private static List<byte[]> blocks(String pem, String type) {
        List<byte[]> result = new ArrayList<>();
        Matcher matcher = BLOCK.matcher(pem == null ? "" : pem);
        while (matcher.find()) {
            if (matcher.group(1).equals(type)) {
                result.add(Base64.getMimeDecoder().decode(matcher.group(2)));
            }
        }
        return result;
    }
}
