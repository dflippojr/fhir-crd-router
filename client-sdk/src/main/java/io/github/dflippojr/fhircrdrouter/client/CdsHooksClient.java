package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.client.auth.MutualTls;
import io.github.dflippojr.fhircrdrouter.client.auth.OAuth2TokenClient;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * Given a resolved {@link ConnectionRecord}, talks to that payer's CDS
 * Hooks endpoint directly — the router itself never does this; only the
 * client SDK does (per the capsule's "optional client SDK" decision).
 *
 * <p>Connections with an {@code mtlsCredentialRef} use a separate
 * {@link HttpClient} per client certificate, built by this class and
 * restricted to TLS 1.2+. The token endpoint for OAuth2 connections is called
 * over that same client. Connections without mutual TLS use the
 * {@code HttpClient} passed to the constructor.
 */
public final class CdsHooksClient {

    private final HttpClient httpClient;
    private final KeyStore mtlsTrustStore;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CredentialProvider credentialProvider;
    private final OAuth2TokenClient oauth2TokenClient;
    private final JwtSigner jwtSigner = new JwtSigner();
    private final Map<String, HttpClient> mtlsClients = new ConcurrentHashMap<>();

    public CdsHooksClient(CredentialProvider credentialProvider) {
        this(HttpClient.newBuilder().sslParameters(MutualTls.sslParameters()).build(), credentialProvider, null);
    }

    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider) {
        this(httpClient, credentialProvider, null);
    }

    /**
     * @param mtlsTrustStore server certificates to trust on mutual TLS connections,
     *     or {@code null} for the JVM default (e.g. to trust a sandbox's private CA)
     */
    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider, KeyStore mtlsTrustStore) {
        this.httpClient = httpClient;
        this.credentialProvider = credentialProvider;
        this.mtlsTrustStore = mtlsTrustStore;
        this.oauth2TokenClient = new OAuth2TokenClient(httpClient);
    }

    /** Calls the payer's standard {@code GET {baseUrl}/cds-services} discovery endpoint. */
    public List<CdsServiceDescriptor> discoverServices(ConnectionRecord record) {
        String context = "Discovery call for payerId=" + record.payerId();
        HttpResponse<String> response = send(record, context, () -> HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(record.baseUrl()) + "/cds-services"))
                .GET());
        try {
            JsonNode servicesNode = mapper.readTree(response.body()).get("services");
            List<CdsServiceDescriptor> services = new ArrayList<>();
            if (servicesNode != null && servicesNode.isArray()) {
                for (JsonNode node : servicesNode) {
                    services.add(mapper.treeToValue(node, CdsServiceDescriptor.class));
                }
            }
            return services;
        } catch (IOException e) {
            throw new RouterException(context + " returned an unparseable body", e);
        }
    }

    /** Invokes a named hook (raw passthrough form). */
    public JsonNode callHookRaw(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        String context = "Hook call for payerId=" + record.payerId() + " serviceId=" + serviceId;
        String body;
        try {
            body = mapper.writeValueAsString(request);
        } catch (IOException e) {
            throw new RouterException(context + " could not serialize request", e);
        }
        HttpResponse<String> response = send(record, context, () -> HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(record.baseUrl()) + "/cds-services/" + serviceId))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body)));
        try {
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new RouterException(context + " returned an unparseable body", e);
        }
    }

    /** Invokes a named hook and also deserializes the {@code cards} and {@code systemActions} arrays. */
    public CdsHookResponse callHook(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        JsonNode raw = callHookRaw(record, serviceId, request);
        return new CdsHookResponse(
                parseArray(record, raw, "cards", Card.class),
                parseArray(record, raw, "systemActions", SystemAction.class),
                raw);
    }

    private <T> List<T> parseArray(ConnectionRecord record, JsonNode raw, String field, Class<T> type) {
        List<T> items = new ArrayList<>();
        for (JsonNode node : raw.path(field)) {
            try {
                items.add(mapper.treeToValue(node, type));
            } catch (IOException e) {
                throw new RouterException("Failed to parse an entry in " + field + " for payerId=" + record.payerId(), e);
            }
        }
        return items;
    }

    /**
     * Sends a request with auth applied. For OAuth2 connections a 401 drops the
     * cached token and retries once with a fresh one, since payers can revoke
     * tokens before their advertised expiry.
     */
    private HttpResponse<String> send(ConnectionRecord record, String context, Supplier<HttpRequest.Builder> requestFactory) {
        try {
            HttpClient client = httpClientFor(record);
            HttpResponse<String> response = sendOnce(client, record, requestFactory);
            if (response.statusCode() == 401 && isOAuth2(record)) {
                oauth2TokenClient.invalidate(record);
                response = sendOnce(client, record, requestFactory);
            }
            if (response.statusCode() / 100 != 2) {
                throw new RouterException(context + " failed: payer returned HTTP " + response.statusCode()
                        + ": " + response.body());
            }
            return response;
        } catch (IOException e) {
            throw new RouterException(context + " failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RouterException(context + " interrupted", e);
        }
    }

    private HttpResponse<String> sendOnce(HttpClient client, ConnectionRecord record,
                                          Supplier<HttpRequest.Builder> requestFactory)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = requestFactory.get();
        URI uri = builder.copy().build().uri();
        applyAuth(client, builder, uri, record);
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void applyAuth(HttpClient client, HttpRequest.Builder builder, URI uri, ConnectionRecord record) {
        switch (record.authType()) {
            case NONE -> { /* no-op */ }
            case API_KEY -> builder.header("Authorization", "Bearer " + requireSecret(record));
            case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_PRIVATE_KEY_JWT -> builder.header("Authorization",
                    "Bearer " + oauth2TokenClient.fetchAccessToken(client, record, requireSecret(record)));
            case CDS_HOOKS_JWT -> builder.header("Authorization",
                    "Bearer " + jwtSigner.cdsHooksJwt(record, PemKeys.readPrivateKey(requireSecret(record)), uri));
        }
    }

    private static boolean isOAuth2(ConnectionRecord record) {
        return record.authType() == AuthType.OAUTH2_CLIENT_CREDENTIALS
                || record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT;
    }

    /** The shared client, or one bound to this record's client certificate when mutual TLS is configured. */
    private HttpClient httpClientFor(ConnectionRecord record) {
        if (record.mtlsCredentialRef() == null) {
            return httpClient;
        }
        String pemBundle = credentialProvider.resolve(record.mtlsCredentialRef())
                .orElseThrow(() -> new RouterException("No mTLS credential found for ref="
                        + record.mtlsCredentialRef() + " (payerId=" + record.payerId() + ")"));
        // Keyed by content hash too, so a rotated certificate gets a fresh client.
        String key = record.mtlsCredentialRef() + "#" + sha256(pemBundle);
        return mtlsClients.computeIfAbsent(key, k -> HttpClient.newBuilder()
                .sslContext(MutualTls.sslContext(pemBundle, mtlsTrustStore))
                .sslParameters(MutualTls.sslParameters())
                .build());
    }

    private static String sha256(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private String requireSecret(ConnectionRecord record) {
        if (record.credentialRef() == null) {
            throw new RouterException("authType=" + record.authType() + " but no credentialRef set for payerId=" + record.payerId());
        }
        return credentialProvider.resolve(record.credentialRef())
                .orElseThrow(() -> new RouterException(
                        "No credential found for ref=" + record.credentialRef() + " (payerId=" + record.payerId() + ")"));
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
