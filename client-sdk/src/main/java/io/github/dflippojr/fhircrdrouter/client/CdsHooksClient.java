package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.auth.JwtSigner;
import io.github.dflippojr.fhircrdrouter.client.auth.MutualTls;
import io.github.dflippojr.fhircrdrouter.client.auth.OAuth2TokenClient;
import io.github.dflippojr.fhircrdrouter.client.auth.PemKeys;
import io.github.dflippojr.fhircrdrouter.client.internal.BearerTokens;
import io.github.dflippojr.fhircrdrouter.client.internal.ExchangeSender;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import io.github.dflippojr.fhircrdrouter.core.audit.AuditPersistenceException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.OptionalInt;
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
    /** Largest response body, in bytes, read from a payer or token endpoint; a longer one fails the call. */
    public static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

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

    /**
     * A credential reference that is unset or does not resolve; keeps the existing message.
     * {@code phase} is null when the credential belongs to the request being sent.
     */
    private static final class MissingCredentialException extends RouterException {
        private final transient PayerCallPhase phase;

        MissingCredentialException(String message, PayerCallPhase phase) {
            super(message);
            this.phase = phase;
        }
    }

    /**
     * The credential provider threw while resolving a reference, for example a key mismatch or an
     * unreadable secrets file. The provider's exception is kept as the cause; its message is not
     * copied, since it may describe secret material. {@code phase} is null as for
     * {@link MissingCredentialException}.
     */
    private static final class CredentialReadException extends RouterException {
        private final transient PayerCallPhase phase;

        CredentialReadException(String message, PayerCallPhase phase, RuntimeException cause) {
            super(message, cause);
            this.phase = phase;
        }
    }

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
        JsonNode raw = discoverServicesRaw(record);
        try {
            JsonNode servicesNode = raw.get("services");
            List<CdsServiceDescriptor> services = new ArrayList<>();
            if (servicesNode != null && servicesNode.isArray()) {
                for (JsonNode node : servicesNode) {
                    CdsServiceDescriptor descriptor = mapper.treeToValue(node, CdsServiceDescriptor.class);
                    if (descriptor == null) {
                        throw new RouterException(context + " returned a null entry in services");
                    }
                    services.add(descriptor);
                }
            }
            return services;
        } catch (IOException e) {
            throw new RouterException(context + " returned an unparseable body", e);
        }
    }

    /**
     * Fetches discovery without coercing descriptor fields. Uses the same authentication,
     * timeouts, retries and exchange listener as typed discovery. Catalog validation is
     * opt-in via {@link CdsDiscoveryValidator#validate(JsonNode)}.
     */
    public JsonNode discoverServicesRaw(ConnectionRecord record) {
        String context = "Discovery call for payerId=" + record.payerId();
        HttpResponse<String> response = sendDiscovery(record, context);
        try {
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new RouterException(context + " returned an unparseable body", e);
        }
    }

    /**
     * Checks that a connection works: makes the discovery exchange (plus the token exchange and
     * configured retries when they apply) through the usual pipeline, so the exchange listener sees
     * it, and validates the catalog with {@link CdsDiscoveryValidator}. Never calls a hook. Payer
     * HTTP, transport, timeout, token and credential failures are reported, not thrown, including a
     * {@link CredentialProvider} that throws. The reason text never includes response bodies,
     * headers, credential contents or exception messages. The one exception is an
     * {@link AuditPersistenceException} from an audited provider, which propagates because the
     * audit protocol says to stop and report; a null record throws {@link NullPointerException}.
     *
     * <p>Runs on a record of any {@link io.github.dflippojr.fhircrdrouter.core.ConnectionStatus}, so an
     * {@code INACTIVE} or {@code DEPRECATED} connection can be checked before it is reactivated;
     * only {@code PayerRouter.resolve} refuses those.
     *
     * <p>The SDK does not write to a store: when {@link ConnectionVerification#ok()} is true, save
     * {@code record.withLastVerifiedAt(report.checkedAt())}.
     */
    public ConnectionVerification verify(ConnectionRecord record) {
        Objects.requireNonNull(record, "record");
        String payerId = record.payerId();
        Environment environment = record.environment();
        Instant checkedAt = Instant.now();
        long started = System.nanoTime();
        try {
            HttpResponse<String> response = sendDiscovery(record, "Discovery call for payerId=" + payerId);
            JsonNode catalog;
            try {
                catalog = mapper.readTree(response.body());
            } catch (IOException e) {
                return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                        PayerCallPhase.DISCOVERY, OptionalInt.of(response.statusCode()),
                        "discovery response is not valid JSON");
            }
            JsonNode services = catalog == null ? null : catalog.get("services");
            List<String> hooks = new ArrayList<>();
            int serviceCount = 0;
            if (services != null && services.isArray()) {
                serviceCount = services.size();
                for (JsonNode service : services) {
                    JsonNode hook = service.get("hook");
                    if (hook != null && hook.isTextual() && !hook.textValue().isBlank()) {
                        hooks.add(hook.textValue());
                    }
                }
            }
            return ConnectionVerification.catalog(payerId, environment, checkedAt, since(started),
                    hooks, serviceCount, CdsDiscoveryValidator.validate(catalog));
        } catch (PayerCallException e) {
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    e.phase(), e.statusCode(), payerCallReason(e));
        } catch (MissingCredentialException e) {
            PayerCallPhase phase = e.phase == null ? PayerCallPhase.DISCOVERY : e.phase;
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "missing credential for " + describe(phase));
        } catch (CredentialReadException e) {
            PayerCallPhase phase = e.phase == null ? PayerCallPhase.DISCOVERY : e.phase;
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "credential could not be read: "
                            + e.getCause().getClass().getSimpleName());
        } catch (RouterException | IllegalArgumentException e) {
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    null, OptionalInt.empty(), "connection could not be verified: " + e.getClass().getSimpleName());
        }
    }

    private static String payerCallReason(PayerCallException e) {
        String request = describe(e.phase());
        if (e.statusCode().isPresent()) {
            return request + " returned HTTP " + e.statusCode().getAsInt();
        }
        return request + (e.timedOut() ? " timed out" : " transport failure");
    }

    private static String describe(PayerCallPhase phase) {
        return switch (phase) {
            case DISCOVERY -> "discovery request";
            case TOKEN -> "token request";
            case HOOK -> "hook request";
        };
    }

    private static Duration since(long startedNanos) {
        return Duration.ofNanos(Math.max(0, System.nanoTime() - startedNanos));
    }

    private HttpResponse<String> sendDiscovery(ConnectionRecord record, String context) {
        return send(record, PayerCallPhase.DISCOVERY, context, null, () -> HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(record.baseUrl()) + "/cds-services"))
                .GET());
    }

    /** Invokes a named hook (raw passthrough form). */
    public JsonNode callHookRaw(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        String segment = encodeServiceId(serviceId);
        String context = "Hook call for payerId=" + record.payerId() + " serviceId=" + serviceId;
        String body;
        try {
            body = mapper.writeValueAsString(request);
        } catch (IOException e) {
            throw new RouterException(context + " could not serialize request", e);
        }
        HttpResponse<String> response = send(record, PayerCallPhase.HOOK, context, body, () -> HttpRequest.newBuilder()
                .uri(URI.create(trimTrailingSlash(record.baseUrl()) + "/cds-services/" + segment))
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
        JsonNode array = raw.path(field);
        if (!array.isMissingNode() && !array.isNull() && !array.isArray()) {
            throw new RouterException("Expected " + field + " to be an array for payerId=" + record.payerId());
        }
        List<T> items = new ArrayList<>();
        for (JsonNode node : array) {
            try {
                T item = mapper.treeToValue(node, type);
                if (item == null) {
                    throw new RouterException("Failed to parse an entry in " + field + " for payerId=" + record.payerId()
                            + ": entry is null");
                }
                items.add(item);
            } catch (IOException e) {
                throw new RouterException("Failed to parse an entry in " + field + " for payerId=" + record.payerId(), e);
            }
        }
        return items;
    }

    /**
     * Percent-encodes a service id as a single RFC 3986 path segment: every byte except the unreserved
     * characters becomes {@code %XX}, so {@code ?}, {@code #} and {@code /} cannot change the request.
     * Rejects ids that would not stay one segment under {@code /cds-services/}.
     */
    private static String encodeServiceId(String serviceId) {
        if (serviceId == null || serviceId.isEmpty() || serviceId.equals(".") || serviceId.equals("..")) {
            throw new IllegalArgumentException("serviceId must not be null, empty, \".\" or \"..\"");
        }
        StringBuilder encoded = new StringBuilder();
        for (byte b : serviceId.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~') {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 0xF, 16)));
            }
        }
        return encoded.toString();
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
            case API_KEY -> builder.header("Authorization", "Bearer " + requireApiKey(record));
            case OAUTH2_CLIENT_CREDENTIALS, OAUTH2_PRIVATE_KEY_JWT -> builder.header("Authorization",
                    "Bearer " + oauth2TokenClient.fetchAccessToken(client, record, () -> requireSecret(record), attempt));
            case CDS_HOOKS_JWT -> builder.header("Authorization",
                    "Bearer " + jwtSigner.cdsHooksJwt(record, PemKeys.readPrivateKey(requireSecret(record)), uri));
        }
    }

    private static boolean isOAuth2(ConnectionRecord record) {
        return record.authType() == AuthType.OAUTH2_CLIENT_CREDENTIALS
                || record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT;
    }

    /** The shared client, or one bound to this record's client certificate when mutual TLS is configured. */
    HttpClient httpClientFor(ConnectionRecord record) {
        if (record.mtlsCredentialRef() == null) {
            return httpClient;
        }
        String pemBundle = resolveCredential(record, record.mtlsCredentialRef(), null)
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

    /** The stored key, which must be a b64token: anything else, e.g. a trailing newline, is not a legal header value. */
    private String requireApiKey(ConnectionRecord record) {
        String key = requireSecret(record);
        if (!BearerTokens.isB64Token(key)) {
            // Never echo the key: it is the credential.
            throw new RouterException("Credential for ref=" + record.credentialRef() + " (payerId="
                    + record.payerId() + ") is not a usable bearer token");
        }
        return key;
    }

    private String requireSecret(ConnectionRecord record) {
        // An OAuth2 secret authenticates the token exchange; any other secret, the request itself.
        PayerCallPhase phase = isOAuth2(record) ? PayerCallPhase.TOKEN : null;
        if (record.credentialRef() == null) {
            throw new MissingCredentialException("authType=" + record.authType()
                    + " but no credentialRef set for payerId=" + record.payerId(), phase);
        }
        return resolveCredential(record, record.credentialRef(), phase)
                .orElseThrow(() -> new MissingCredentialException(
                        "No credential found for ref=" + record.credentialRef() + " (payerId=" + record.payerId() + ")", phase));
    }

    /**
     * Resolves a reference, wrapping a provider failure in a {@link RouterException} that keeps the
     * original as its cause. An {@link AuditPersistenceException} is not wrapped: callers must see it.
     */
    private Optional<String> resolveCredential(ConnectionRecord record, String ref, PayerCallPhase phase) {
        try {
            return credentialProvider.resolve(ref);
        } catch (AuditPersistenceException e) {
            throw e;
        } catch (RuntimeException e) {
            throw new CredentialReadException("Failed to read credential for ref=" + ref
                    + " (payerId=" + record.payerId() + ")", phase, e);
        }
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
