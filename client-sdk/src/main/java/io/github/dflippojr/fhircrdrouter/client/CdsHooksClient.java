package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.client.auth.MutualTls;
import io.github.dflippojr.fhircrdrouter.client.auth.OAuth2TokenClient;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.client.internal.ExchangeSender;
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
import java.time.Duration;
import java.util.Objects;
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
 * {@link HttpClient} per credential reference, built by this class and
 * restricted to TLS 1.2+. The token endpoint for OAuth2 connections is called
 * over that same client. Connections without mutual TLS use the
 * {@code HttpClient} passed to the constructor.
 */
public final class CdsHooksClient {

    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(10);
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);

    private final PayerExchangeListener exchangeListener;
    private final Duration requestTimeout;
    private final Duration connectTimeout;
    private final HttpClient httpClient;
    private final KeyStore mtlsTrustStore;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CredentialProvider credentialProvider;
    private final OAuth2TokenClient oauth2TokenClient;
    private final JwtSigner jwtSigner = new JwtSigner();
    private volatile RetryPolicy retryPolicy = RetryPolicy.NONE;
    private final Map<String, MtlsClient> mtlsClients = new ConcurrentHashMap<>();

    private record MtlsClient(String fingerprint, HttpClient client) { }

    public CdsHooksClient(CredentialProvider credentialProvider) {
        this(credentialProvider, DEFAULT_REQUEST_TIMEOUT, DEFAULT_CONNECT_TIMEOUT);
    }

    /** Builds the default client with explicit request and connection budgets. */
    public CdsHooksClient(CredentialProvider credentialProvider, Duration requestTimeout, Duration connectTimeout) {
        this(credentialProvider, requestTimeout, connectTimeout, PayerExchangeListener.NOOP);
    }

    /** Builds the default client with timeouts and a redacted exchange listener. */
    public CdsHooksClient(CredentialProvider credentialProvider, Duration requestTimeout, Duration connectTimeout,
                          PayerExchangeListener exchangeListener) {
        this(HttpClient.newBuilder().sslParameters(MutualTls.sslParameters())
                .connectTimeout(positiveTimeout(connectTimeout)).build(), credentialProvider, null,
                requestTimeout, connectTimeout, exchangeListener);
    }

    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider) {
        this(httpClient, credentialProvider, null);
    }

    /**
     * @param mtlsTrustStore server certificates to trust on mutual TLS connections,
     *     or {@code null} for the JVM default (e.g. to trust a sandbox's private CA)
     */
    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider, KeyStore mtlsTrustStore) {
        this(httpClient, credentialProvider, mtlsTrustStore, DEFAULT_REQUEST_TIMEOUT, DEFAULT_CONNECT_TIMEOUT);
    }

    /** A supplied client retains its own connect timeout; connectTimeout applies to SDK-built mTLS clients. */
    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider, KeyStore mtlsTrustStore,
                          Duration requestTimeout, Duration connectTimeout) {
        this(httpClient, credentialProvider, mtlsTrustStore, requestTimeout, connectTimeout, PayerExchangeListener.NOOP);
    }

    /** Same timeout semantics, with a listener invoked after each HTTP attempt. */
    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider, KeyStore mtlsTrustStore,
                          Duration requestTimeout, Duration connectTimeout, PayerExchangeListener exchangeListener) {
        this.exchangeListener = Objects.requireNonNull(exchangeListener, "exchangeListener");
        this.requestTimeout = positiveTimeout(requestTimeout);
        this.connectTimeout = positiveTimeout(connectTimeout);
        this.httpClient = Objects.requireNonNull(httpClient);
        this.credentialProvider = credentialProvider;
        this.mtlsTrustStore = mtlsTrustStore;
        this.oauth2TokenClient = new OAuth2TokenClient(httpClient, requestTimeout, exchangeListener);
    }

    /**
     * Opts in to bounded retry of 429 and 503 responses that carry {@code Retry-After}; off by default.
     * Each attempt is reported to the {@link PayerExchangeListener}. CDS Hooks calls are interactive,
     * so keep the limits small. Returns this client.
     */
    public CdsHooksClient retryPolicy(RetryPolicy policy) {
        this.retryPolicy = Objects.requireNonNull(policy, "policy");
        return this;
    }

    /** Calls the payer's standard {@code GET {baseUrl}/cds-services} discovery endpoint. */
    public List<CdsServiceDescriptor> discoverServices(ConnectionRecord record) {
        String context = "Discovery call for payerId=" + record.payerId();
        HttpResponse<String> response = send(record, PayerCallPhase.DISCOVERY, context, null, () -> HttpRequest.newBuilder()
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
        HttpResponse<String> response = send(record, PayerCallPhase.HOOK, context, body, () -> HttpRequest.newBuilder()
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
    private HttpResponse<String> send(ConnectionRecord record, PayerCallPhase phase, String context, String body, Supplier<HttpRequest.Builder> requestFactory) {
        URI uri = requestFactory.get().build().uri();
        try {
            HttpClient client = httpClientFor(record);
            RetryPolicy policy = retryPolicy;
            int attempt = 1;
            int throttleRetries = 0;
            boolean reauthenticated = false;
            Duration waited = Duration.ZERO;
            while (true) {
                HttpResponse<String> response = sendOnce(client, record, phase, body, attempt, requestFactory);
                int status = response.statusCode();
                if (status / 100 == 2) {
                    return response;
                }
                if (status == 401 && isOAuth2(record) && !reauthenticated) {
                    reauthenticated = true;
                    oauth2TokenClient.invalidate(record);
                    attempt++;
                    continue;
                }
                PayerCallException failure = new PayerCallException(context + " failed: payer returned HTTP "
                        + status + ": ", phase, record.payerId(), uri, response, response.body());
                Duration wait = policy.enabled() && RetryPolicy.retryable(status)
                        && throttleRetries + 1 < policy.maxAttempts()
                        ? failure.retryAfter().orElse(null) : null;
                if (wait == null || wait.compareTo(policy.maxTotalWait().minus(waited)) > 0) {
                    throw failure;
                }
                sleep(wait);
                waited = waited.plus(wait);
                throttleRetries++;
                attempt++;
            }
        } catch (IOException e) {
            throw PayerCallException.transport(context + " failed", phase, record.payerId(), uri, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw PayerCallException.transport(context + " interrupted", phase, record.payerId(), uri, e);
        }
    }

    private static void sleep(Duration wait) throws InterruptedException {
        if (!wait.isZero()) {
            Thread.sleep(wait.toMillis() + (wait.toNanosPart() % 1_000_000 == 0 ? 0 : 1));
        }
    }

    private HttpResponse<String> sendOnce(HttpClient client, ConnectionRecord record,
                                          PayerCallPhase phase, String body, int attempt,
                                          Supplier<HttpRequest.Builder> requestFactory)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = requestFactory.get().timeout(requestTimeout);
        URI uri = builder.copy().build().uri();
        applyAuth(client, builder, uri, record, attempt);
        return ExchangeSender.send(client, builder.build(), body, record, phase, attempt, exchangeListener);
    }

    private void applyAuth(HttpClient client, HttpRequest.Builder builder, URI uri, ConnectionRecord record, int attempt) {
        switch (record.authType()) {
            case NONE -> { /* no-op */ }
            case API_KEY -> builder.header("Authorization", "Bearer " + requireSecret(record));
            case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_PRIVATE_KEY_JWT -> builder.header("Authorization",
                    "Bearer " + oauth2TokenClient.fetchAccessToken(client, record, requireSecret(record), attempt));
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

    private static Duration positiveTimeout(Duration timeout) {
        Objects.requireNonNull(timeout, "timeout");
        if (timeout.isZero() || timeout.isNegative()) {
            throw new IllegalArgumentException("timeout must be positive");
        }
        return timeout;
    }

    private static String trimTrailingSlash(String url) {
        return url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
