package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CredentialLookup.CredentialReadException;
import io.github.dflippojr.fhircrdrouter.client.CredentialLookup.MissingCredentialException;
import io.github.dflippojr.fhircrdrouter.client.auth.MutualTls;
import io.github.dflippojr.fhircrdrouter.client.internal.EhrRedaction;
import io.github.dflippojr.fhircrdrouter.client.internal.EndpointUrls;
import io.github.dflippojr.fhircrdrouter.client.internal.SecretScrubber;
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
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.OptionalInt;

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
 *
 * <p>Every call first checks the record's URLs ({@code baseUrl}, {@code tokenEndpoint} for OAuth2,
 * {@code jwksUrl} when a JWT is signed): each must be an absolute {@code https} URL with a host, or
 * {@code http} to a loopback host. Anything else throws {@link EndpointUrlException} before a
 * credential is read or a request is sent (CDS Hooks 2.0,
 * <a href="https://cds-hooks.hl7.org/2.0/#security-and-safety">Security and Safety</a>). A supplied
 * {@code HttpClient} must not follow redirects ({@link HttpClient.Redirect#NEVER}, the JDK default), since a
 * followed redirect is never checked; the constructor throws {@link IllegalArgumentException} for one that does.
 */
public final class CdsHooksClient {

    public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(10);
    public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
    /** Largest response body, in bytes, read from a payer or token endpoint; a longer one fails the call. */
    public static final int MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

    private final ObjectMapper mapper = new ObjectMapper();
    private final MtlsClients mtlsClients;
    private final PayerCallLoop payerCalls;

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
        Objects.requireNonNull(exchangeListener, "exchangeListener");
        positiveTimeout(requestTimeout);
        positiveTimeout(connectTimeout);
        // A followed redirect would bypass the https check on the record's URLs (#156).
        EndpointUrls.requireNoRedirects(Objects.requireNonNull(httpClient));
        CredentialLookup credentials = new CredentialLookup(credentialProvider);
        this.mtlsClients = new MtlsClients(httpClient, credentials, mtlsTrustStore, connectTimeout);
        this.payerCalls = new PayerCallLoop(httpClient, requestTimeout, exchangeListener, mtlsClients, credentials);
    }

    /**
     * Opts in to bounded retry of 429 and 503 responses that carry {@code Retry-After}; off by default.
     * Each attempt is reported to the {@link PayerExchangeListener}. CDS Hooks calls are interactive,
     * so keep the limits small. Returns this client.
     */
    public CdsHooksClient retryPolicy(RetryPolicy policy) {
        payerCalls.retryPolicy(Objects.requireNonNull(policy, "policy"));
        return this;
    }

    /** Calls the payer's standard {@code GET {baseUrl}/cds-services} discovery endpoint. */
    public List<CdsServiceDescriptor> discoverServices(ConnectionRecord record) {
        String context = discoveryContext(record);
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
        String context = discoveryContext(record);
        return readBody(sendDiscovery(record, context, null), context);
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
     * <p>An OAuth2 connection always exchanges a fresh token: exactly one token request per call, whatever
     * the cache holds, so a secret rotated to a bad value fails here rather than when the cached token
     * expires (#218). That token is used only for this call, including its configured retries. A discovery
     * 401 is reported without a second exchange. The token cache is neither read nor changed, so payer calls
     * are unaffected by a failed {@code verify} and are not refreshed by a successful one.
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
            HttpResponse<String> response = sendDiscovery(record, discoveryContext(record), payerCalls.freshToken());
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
            PayerCallPhase phase = e.phaseOrDiscovery();
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "missing credential for " + describe(phase));
        } catch (CredentialReadException e) {
            PayerCallPhase phase = e.phaseOrDiscovery();
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    phase, OptionalInt.empty(), "credential could not be read: "
                            + e.getCause().getClass().getSimpleName());
        } catch (EndpointUrlException e) {
            // No exchange was attempted, so no phase; the problem text never includes the URL.
            return ConnectionVerification.failure(payerId, environment, checkedAt, since(started),
                    null, OptionalInt.empty(), e.field() + " " + e.problem());
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

    private static String discoveryContext(ConnectionRecord record) {
        return "Discovery call for payerId=" + record.payerId();
    }

    /** {@code {baseUrl}/cds-services}, with one slash however the base URL ends. */
    private static String servicesUrl(ConnectionRecord record) {
        return trimTrailingSlash(record.baseUrl()) + "/cds-services";
    }

    private JsonNode readBody(HttpResponse<String> response, String context) {
        return readBody(response, context, null);
    }

    /** Reads a JSON body; a parse error that quotes {@code ehrToken} is reported without it (#164). */
    private JsonNode readBody(HttpResponse<String> response, String context, String ehrToken) {
        try {
            return mapper.readTree(response.body());
        } catch (IOException e) {
            throw new RouterException(context + " returned an unparseable body", withoutToken(e, ehrToken));
        }
    }

    /** {@code error}, or a copy of it without {@code ehrToken} in its diagnostics if any of them shows it. */
    private static Exception withoutToken(Exception error, String ehrToken) {
        return ehrToken == null ? error : SecretScrubber.safeError(error, ehrToken, false);
    }

    private static String ehrToken(CdsHookRequest request) {
        return request.fhirAuthorization() == null ? null : request.fhirAuthorization().accessToken();
    }

    private HttpResponse<String> sendDiscovery(ConnectionRecord record, String context,
                                               PayerCallLoop.FreshToken freshToken) {
        return payerCalls.send(record, PayerCallPhase.DISCOVERY, context, null, freshToken, () -> HttpRequest.newBuilder()
                .uri(URI.create(servicesUrl(record)))
                .GET());
    }

    /**
     * Invokes a named hook (raw passthrough form). The request's EHR {@code fhirAuthorization} token is
     * kept out of every listener exchange and every exception of the call (#164).
     */
    public JsonNode callHookRaw(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        EhrRedaction redaction = EhrRedaction.of(ehrToken(request));
        try (EhrRedaction.Scope ignored = redaction.open()) {
            String segment = encodeServiceId(serviceId);
            String context = "Hook call for payerId=" + record.payerId() + " serviceId=" + serviceId;
            String body;
            try {
                body = mapper.writeValueAsString(request);
            } catch (IOException e) {
                throw new RouterException(context + " could not serialize request", withoutToken(e, ehrToken(request)));
            }
            HttpResponse<String> response = payerCalls.send(record, PayerCallPhase.HOOK, context, body, null,
                    () -> HttpRequest.newBuilder()
                    .uri(URI.create(servicesUrl(record) + "/" + segment))
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(body)));
            return readBody(response, context, ehrToken(request));
        } catch (RuntimeException e) {
            throw redaction.exception(e);
        }
    }

    /** Invokes a named hook and also deserializes the {@code cards} and {@code systemActions} arrays. */
    public CdsHookResponse callHook(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        EhrRedaction redaction = EhrRedaction.of(ehrToken(request));
        try (EhrRedaction.Scope ignored = redaction.open()) {
            JsonNode raw = callHookRaw(record, serviceId, request);
            // CDS Hooks 2.0 HTTP Response (https://cds-hooks.hl7.org/2.0/#http-response): the body is a JSON
            // object. Any other root would read as "no cards", so it fails instead. The body is not echoed.
            if (raw == null || !raw.isObject()) {
                throw new RouterException("Hook call for payerId=" + record.payerId() + " serviceId=" + serviceId
                        + " returned a response body that is not a JSON object");
            }
            return new CdsHookResponse(
                    parseArray(record, raw, "cards", Card.class, ehrToken(request)),
                    parseArray(record, raw, "systemActions", SystemAction.class, ehrToken(request)),
                    raw);
        } catch (RuntimeException e) {
            throw redaction.exception(e);
        }
    }

    private <T> List<T> parseArray(ConnectionRecord record, JsonNode raw, String field, Class<T> type,
                                   String ehrToken) {
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
                throw new RouterException("Failed to parse an entry in " + field + " for payerId=" + record.payerId(),
                        withoutToken(e, ehrToken));
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

    /** {@link MtlsClients#httpClientFor}, exposed within the package for the mTLS rotation tests. */
    HttpClient httpClientFor(ConnectionRecord record) {
        return mtlsClients.httpClientFor(record);
    }

    /** Number of retained mTLS clients, exposed within the package for retention tests. */
    int mtlsClientCount() {
        return mtlsClients.mtlsClientCount();
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
