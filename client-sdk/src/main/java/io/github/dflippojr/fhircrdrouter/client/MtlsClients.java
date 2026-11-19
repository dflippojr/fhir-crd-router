package io.github.dflippojr.fhircrdrouter.client;

import io.github.dflippojr.fhircrdrouter.client.CredentialLookup.MissingCredentialException;
import io.github.dflippojr.fhircrdrouter.client.auth.MutualTls;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * The {@link HttpClient} each {@link CdsHooksClient} call uses: the one passed to its constructor, or one per
 * mutual TLS credential reference, kept with the fingerprint of the PEM bundle it was built from, so a rotated
 * bundle gets a new client.
 */
final class MtlsClients {
    private final HttpClient httpClient;
    private final CredentialLookup credentials;
    private final KeyStore mtlsTrustStore;
    private final Duration connectTimeout;
    private final Map<String, MtlsClient> mtlsClients = new ConcurrentHashMap<>();

    private record MtlsClient(String fingerprint, HttpClient client) { }

    MtlsClients(HttpClient httpClient, CredentialLookup credentials, KeyStore mtlsTrustStore,
                Duration connectTimeout) {
        this.httpClient = httpClient;
        this.credentials = credentials;
        this.mtlsTrustStore = mtlsTrustStore;
        this.connectTimeout = connectTimeout;
    }

    /** The shared client, or one bound to this record's client certificate when mutual TLS is configured. */
    HttpClient httpClientFor(ConnectionRecord record) {
        if (record.mtlsCredentialRef() == null) {
            return httpClient;
        }
        String pemBundle = credentials.resolveCredential(record, record.mtlsCredentialRef(), null)
                .orElseThrow(() -> new MissingCredentialException("No mTLS credential found for ref="
                        + record.mtlsCredentialRef() + " (payerId=" + record.payerId() + ")", null));
        String fingerprint = sha256(pemBundle);
        // Build before publishing: a failure leaves the previous entry intact.
        // Replacing the entry releases our old reference; in-flight calls keep theirs.
        return mtlsClients.compute(record.mtlsCredentialRef(), (ref, current) -> {
            if (current != null && current.fingerprint().equals(fingerprint)) {
                return current;
            }
            HttpClient replacement = HttpClient.newBuilder()
                    .connectTimeout(connectTimeout)
                    .sslContext(MutualTls.sslContext(pemBundle, mtlsTrustStore))
                    .sslParameters(MutualTls.sslParameters())
                    .build();
            return new MtlsClient(fingerprint, replacement);
        }).client();
    }

    /** Number of retained mTLS clients, exposed within the package for retention tests. */
    int mtlsClientCount() {
        return mtlsClients.size();
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }
}
