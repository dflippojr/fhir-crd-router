package io.github.dflippojr.fhircrdrouter.client.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.CdsHooksClient;
import io.github.dflippojr.fhircrdrouter.client.PayerCallException;
import io.github.dflippojr.fhircrdrouter.client.PayerCallPhase;
import io.github.dflippojr.fhircrdrouter.client.PayerExchangeListener;
import io.github.dflippojr.fhircrdrouter.client.internal.BearerTokens;
import io.github.dflippojr.fhircrdrouter.client.internal.EchoedCredentials;
import io.github.dflippojr.fhircrdrouter.client.internal.EndpointUrls;
import io.github.dflippojr.fhircrdrouter.client.internal.ExchangeSender;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Supplier;

/**
 * OAuth2 client-credentials token fetch for
 * {@code OAUTH2_CLIENT_CREDENTIALS} and {@code OAUTH2_PRIVATE_KEY_JWT} connections.
 *
 * <p>Follows RFC 6749: the client ID is a non-secret identifier stored on
 * the record ({@link ConnectionRecord#clientId()}), and only the client
 * secret lives behind {@code credentialRef}. The pair is sent with the
 * {@code client_secret_basic} method (HTTP Basic, each part form-urlencoded
 * first per §2.3.1), which authorization servers are required to support.
 *
 * <p>For {@code OAUTH2_PRIVATE_KEY_JWT}, {@code credentialRef} instead
 * resolves to a PEM private key, and the client authenticates with a signed
 * {@code client_assertion} (RFC 7523, as profiled by SMART Backend Services).
 *
 * <p>Tokens are cached in memory per (token endpoint, client ID, scopes,
 * mTLS credential ref), so records that reach the token endpoint under different
 * client certificates, or one with and one without mTLS, never share a
 * (possibly certificate-bound, RFC 8705) token. Entries last
 * until {@code expires_in} minus {@link #EXPIRY_SKEW}, with {@code expires_in}
 * capped at {@link #MAX_CACHE_LIFETIME}. {@code expires_in} may be a positive whole
 * number or, for servers that send it as a string, a numeric string such as
 * {@code "3600"}; a token response with no {@code expires_in}, or any other value
 * ({@code "abc"}, {@code "1.5"}, {@code "0"}, {@code null}), is not cached. One whose {@code access_token} is not
 * a string in the RFC 6750 {@code b64token} form is rejected with a {@link RouterException}
 * and never cached. Callers that get a 401 from the
 * payer should {@link #invalidate} and fetch again, since a payer can revoke
 * a token before its advertised expiry.
 *
 * <p>{@code tokenEndpoint}, and {@code jwksUrl} for {@code OAUTH2_PRIVATE_KEY_JWT}, must be an absolute
 * {@code https} URL, or {@code http} to a loopback host; anything else throws
 * {@link io.github.dflippojr.fhircrdrouter.client.EndpointUrlException} before a cached token is returned,
 * the secret is resolved or a request is sent (CDS Hooks 2.0,
 * <a href="https://cds-hooks.hl7.org/2.0/#security-and-safety">Security and Safety</a>). Every
 * {@link HttpClient}, the constructor's and one passed to {@code fetchAccessToken}, must not follow
 * redirects ({@link HttpClient.Redirect#NEVER}, the JDK default): one that does throws
 * {@link IllegalArgumentException}, since a redirect would carry the secret to an unchecked URL.
 */
public final class OAuth2TokenClient {

    /** Refresh this long before the advertised expiry to avoid racing it. */
    static final Duration EXPIRY_SKEW = Duration.ofSeconds(30);

    /** Longest a token is cached, whatever {@code expires_in} advertises. */
    static final Duration MAX_CACHE_LIFETIME = Duration.ofHours(24);

    private final PayerExchangeListener exchangeListener;
    private final Duration requestTimeout;
    private final HttpClient httpClient;
    private final Clock clock;
    private final JwtSigner jwtSigner;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<CacheKey, CachedToken> cache = new ConcurrentHashMap<>();
    private final Map<CacheKey, CompletableFuture<CachedToken>> inFlight = new ConcurrentHashMap<>();

    public OAuth2TokenClient(HttpClient httpClient) {
        this(httpClient, CdsHooksClient.DEFAULT_REQUEST_TIMEOUT);
    }

    public OAuth2TokenClient(HttpClient httpClient, Duration requestTimeout) {
        this(httpClient, requestTimeout, PayerExchangeListener.NOOP);
    }

    public OAuth2TokenClient(HttpClient httpClient, Duration requestTimeout, PayerExchangeListener exchangeListener) {
        this(httpClient, Clock.systemUTC(), requestTimeout, exchangeListener);
    }

    OAuth2TokenClient(HttpClient httpClient, Clock clock) {
        this(httpClient, clock, CdsHooksClient.DEFAULT_REQUEST_TIMEOUT, PayerExchangeListener.NOOP);
    }

    private OAuth2TokenClient(HttpClient httpClient, Clock clock, Duration requestTimeout,
                              PayerExchangeListener exchangeListener) {
        this.exchangeListener = Objects.requireNonNull(exchangeListener);
        this.requestTimeout = Objects.requireNonNull(requestTimeout);
        if (requestTimeout.isNegative() || requestTimeout.isZero()) {
            throw new IllegalArgumentException("requestTimeout must be positive");
        }
        this.httpClient = EndpointUrls.requireNoRedirects(Objects.requireNonNull(httpClient, "httpClient"));
        this.clock = clock;
        this.jwtSigner = new JwtSigner(clock);
    }

    /** Returns a cached, unexpired token if one exists; otherwise fetches a new one. */
    public String fetchAccessToken(ConnectionRecord record, String secret) {
        return fetchAccessToken(httpClient, record, secret);
    }

    /**
     * Same as {@link #fetchAccessToken(ConnectionRecord, String)}, over a specific
     * client, e.g. one configured for mutual TLS to the token endpoint.
     *
     * @param secret the client secret, or the PEM private key for {@code OAUTH2_PRIVATE_KEY_JWT}
     */
    public String fetchAccessToken(HttpClient client, ConnectionRecord record, String secret) {
        return fetchAccessToken(client, record, secret, 1);
    }

    /** Carries the payer attempt number through a token refresh after a 401. */
    public String fetchAccessToken(HttpClient client, ConnectionRecord record, String secret, int attempt) {
        return fetchAccessToken(client, record, () -> secret, attempt);
    }

    /**
     * Same as {@link #fetchAccessToken(HttpClient, ConnectionRecord, String, int)}, but
     * resolves the secret only when a token request is actually sent. Calls served
     * from the cache, and callers that join another caller's in-flight fetch, never
     * invoke {@code secret}. A failure thrown by {@code secret} fails that fetch for
     * every caller waiting on it.
     *
     * @param secret supplies the client secret, or the PEM private key for {@code OAUTH2_PRIVATE_KEY_JWT}
     */
    public String fetchAccessToken(HttpClient client, ConnectionRecord record, Supplier<String> secret, int attempt) {
        Objects.requireNonNull(secret, "secret");
        // The client secret or assertion must never go to the token endpoint in cleartext, directly or through
        // a redirect, and the assertion's jku must be https too (#156). jwksUrl is not in the cache key.
        EndpointUrls.requireNoRedirects(client);
        URI endpoint = EndpointUrls.requireTokenUrls(record);
        CacheKey key = cacheKey(record);
        CachedToken cached = cache.get(key);
        if (cached != null && clock.instant().isBefore(cached.refreshAt())) {
            return cached.accessToken();
        }
        CompletableFuture<CachedToken> mine = new CompletableFuture<>();
        CompletableFuture<CachedToken> existing = inFlight.putIfAbsent(key, mine);
        if (existing != null) {
            return await(existing).accessToken();
        }
        try {
            // A previous flight may have finished between the cache read above and claiming the slot.
            cached = cache.get(key);
            CachedToken result;
            if (cached != null && clock.instant().isBefore(cached.refreshAt())) {
                result = cached;
            } else {
                result = requestToken(client, record, endpoint, secret.get(), attempt);
                // invalidate() during the flight detaches it: its result must not repopulate the cache.
                if (inFlight.get(key) == mine) {
                    if (result.refreshAt() != null) {
                        cache.put(key, result);
                    } else {
                        cache.remove(key);
                    }
                }
            }
            mine.complete(result);
            return result.accessToken();
        } catch (RuntimeException | Error e) {
            mine.completeExceptionally(e);
            throw e;
        } finally {
            inFlight.remove(key, mine);
        }
    }

    private static CachedToken await(CompletableFuture<CachedToken> flight) {
        try {
            return flight.join();
        } catch (CompletionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof RuntimeException re) {
                throw re;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw e;
        }
    }

    /** Drops any cached token for this connection, e.g. after the payer returns 401. */
    public void invalidate(ConnectionRecord record) {
        CacheKey key = cacheKey(record);
        cache.remove(key);
        // Do not cancel a running fetch, but stop new callers joining it: it may hold the revoked token.
        inFlight.remove(key);
    }

    private CachedToken requestToken(HttpClient client, ConnectionRecord record, URI endpoint, String secret,
                                     int attempt) {
        List<String> scopes = record.scopes();
        StringBuilder form = new StringBuilder("grant_type=client_credentials");
        if (!scopes.isEmpty()) {
            form.append("&scope=").append(formEncode(String.join(" ", scopes)));
        }
        HttpRequest.Builder builder = HttpRequest.newBuilder()
                .uri(endpoint)
                .timeout(requestTimeout)
                .header("Content-Type", "application/x-www-form-urlencoded");

        // The credential this request puts on the wire, which the token server may echo in its error.
        String sentCredential;
        if (record.authType() == AuthType.OAUTH2_PRIVATE_KEY_JWT) {
            String assertion = jwtSigner.clientAssertion(record, PemKeys.readPrivateKey(secret));
            form.append("&client_assertion_type=").append(formEncode(JwtSigner.CLIENT_ASSERTION_TYPE))
                    .append("&client_assertion=").append(formEncode(assertion));
            sentCredential = assertion;
        } else {
            sentCredential = secret;
            String credentials = formEncode(record.clientId()) + ":" + formEncode(secret);
            builder.header("Authorization", "Basic "
                    + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        }

        try {
            HttpRequest request = builder.POST(HttpRequest.BodyPublishers.ofString(form.toString())).build();

            Instant requestedAt = clock.instant();
            HttpResponse<String> response = ExchangeSender.send(client, request, null, record, PayerCallPhase.TOKEN, attempt, exchangeListener);
            if (response.statusCode() / 100 != 2) {
                throw new PayerCallException("Token request failed for payerId=" + record.payerId()
                        + " status=" + response.statusCode() + " body=", PayerCallPhase.TOKEN,
                        record.payerId(), request.uri(), response, tokenErrorBody(response.body(), sentCredential));
            }

            JsonNode json;
            try {
                json = mapper.readTree(response.body());
            } catch (IOException e) {
                // Jackson parse errors can include source content: never attach a token body or its parser cause.
                throw new RouterException("Token response for payerId=" + record.payerId() + " returned an unparseable body");
            }
            JsonNode accessToken = json == null ? null : json.get("access_token");
            // JSON null, objects, arrays and numbers would stringify to "null", "" or digits and be sent as a bearer token.
            // Text outside b64token (controls, CR/LF, non-Latin-1) is not a legal header value: the JDK would throw.
            if (accessToken == null || !accessToken.isTextual() || !BearerTokens.isB64Token(accessToken.textValue())) {
                throw new RouterException("Token response for payerId=" + record.payerId()
                        + " had no usable access_token");
            }

            // Measure expiry from when the request was sent, not when it returned.
            long expiresIn = expiresInSeconds(json.get("expires_in"));
            Instant refreshAt = null;
            if (expiresIn > 0) {
                // Clamp first: a huge value would overflow Instant and throw DateTimeException.
                long seconds = Math.min(expiresIn, MAX_CACHE_LIFETIME.toSeconds());
                refreshAt = requestedAt.plusSeconds(seconds).minus(EXPIRY_SKEW);
            }
            return new CachedToken(accessToken.textValue(), refreshAt);
        } catch (IOException e) {
            throw PayerCallException.transport("Token request I/O failure for payerId=" + record.payerId(),
                    PayerCallPhase.TOKEN, record.payerId(), endpoint, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw PayerCallException.transport("Token request interrupted for payerId=" + record.payerId(),
                    PayerCallPhase.TOKEN, record.payerId(), endpoint, e);
        }
    }

    /**
     * {@code expires_in} in seconds, or 0 when it is absent or unusable. RFC 6749 §5.1 makes it a
     * number, but some servers (older Azure AD endpoints) send a string such as {@code "3600"},
     * which is accepted when it parses as a whole number (#105).
     */
    private static long expiresInSeconds(JsonNode expiresIn) {
        if (expiresIn == null) {
            return 0;
        }
        if (expiresIn.canConvertToLong()) {
            return expiresIn.asLong();
        }
        if (expiresIn.isTextual()) {
            try {
                return Long.parseLong(expiresIn.textValue().trim());
            } catch (NumberFormatException e) {
                // "abc", "", "1.5", "1e3" or out of range: not cached, as for any other unusable value.
            }
        }
        return 0;
    }

    /**
     * Keeps only the RFC 6749 §5.2 (https://www.rfc-editor.org/rfc/rfc6749#section-5.2) {@code error} and
     * {@code error_description}, with {@code sentCredential} redacted: §5.2 lets {@code error_description}
     * be any human-readable text, so a server can echo what it rejected. That is the client secret for
     * {@code client_secret_basic}, or for {@code OAUTH2_PRIVATE_KEY_JWT} the signed {@code client_assertion},
     * which RFC 7523 §2.2 (https://www.rfc-editor.org/rfc/rfc7523#section-2.2) makes the client's credential:
     * a bearer at any server that does not enforce {@code jti} uniqueness until it expires (#195).
     */
    private String tokenErrorBody(String body, String sentCredential) {
        var safe = mapper.createObjectNode();
        try {
            JsonNode json = mapper.readTree(body);
            for (String field : List.of("error", "error_description")) {
                if (json != null && json.path(field).isTextual()) {
                    safe.put(field, EchoedCredentials.redact(json.get(field).asText(), sentCredential));
                }
            }
        } catch (IOException e) {
            // Non-JSON errors have no RFC 6749 fields; omit the raw body.
        }
        return safe.toString();
    }

    // tokenEndpoint and clientId presence are already enforced by ConnectionRecord for this authType.
    private static CacheKey cacheKey(ConnectionRecord record) {
        return new CacheKey(record.tokenEndpoint(), record.clientId(), record.scopes(), record.mtlsCredentialRef());
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    /** {@code mtlsCredentialRef} is null for records without mTLS. */
    private record CacheKey(String tokenEndpoint, String clientId, List<String> scopes, String mtlsCredentialRef) { }

    private record CachedToken(String accessToken, Instant refreshAt) { }
}
