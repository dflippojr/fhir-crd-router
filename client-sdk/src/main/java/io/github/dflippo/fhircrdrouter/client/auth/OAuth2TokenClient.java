package io.github.dflippo.fhircrdrouter.client.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippo.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippo.fhircrdrouter.core.RouterException;

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
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth2 client-credentials token fetch for
 * {@code authType = OAUTH2_CLIENT_CREDENTIALS} connections.
 *
 * <p><b>Assumption (not yet in the locked schema):</b> the schema's
 * {@code credentialRef} resolves to a single secret string, but client
 * credentials grants need both a client ID and secret. Until the schema
 * grows an explicit {@code clientId} field, this expects the resolved
 * secret to be the pair encoded as {@code "clientId:clientSecret"}, sent as
 * HTTP Basic auth to the token endpoint (the common convention, e.g. per
 * RFC 6749 §2.3.1). Revisit if that turns out to be too limiting.
 *
 * <p>Tokens are cached in memory per (token endpoint, client ID, scopes)
 * until {@code expires_in} minus {@link #EXPIRY_SKEW}. A token response
 * without {@code expires_in} is not cached. Callers that get a 401 from the
 * payer should {@link #invalidate} and fetch again, since a payer can revoke
 * a token before its advertised expiry.
 */
public final class OAuth2TokenClient {

    /** Refresh this long before the advertised expiry to avoid racing it. */
    static final Duration EXPIRY_SKEW = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final Clock clock;
    private final ObjectMapper mapper = new ObjectMapper();
    private final Map<CacheKey, CachedToken> cache = new ConcurrentHashMap<>();

    public OAuth2TokenClient(HttpClient httpClient) {
        this(httpClient, Clock.systemUTC());
    }

    OAuth2TokenClient(HttpClient httpClient, Clock clock) {
        this.httpClient = httpClient;
        this.clock = clock;
    }

    /** Returns a cached, unexpired token if one exists; otherwise fetches a new one. */
    public String fetchAccessToken(ConnectionRecord record, String resolvedClientIdAndSecret) {
        CacheKey key = cacheKey(record, resolvedClientIdAndSecret);
        CachedToken cached = cache.get(key);
        if (cached != null && clock.instant().isBefore(cached.refreshAt())) {
            return cached.accessToken();
        }
        CachedToken fresh = requestToken(record, resolvedClientIdAndSecret);
        if (fresh.refreshAt() != null) {
            cache.put(key, fresh);
        } else {
            cache.remove(key);
        }
        return fresh.accessToken();
    }

    /** Drops any cached token for this connection, e.g. after the payer returns 401. */
    public void invalidate(ConnectionRecord record, String resolvedClientIdAndSecret) {
        cache.remove(cacheKey(record, resolvedClientIdAndSecret));
    }

    private CachedToken requestToken(ConnectionRecord record, String resolvedClientIdAndSecret) {
        String basicAuth = Base64.getEncoder().encodeToString(
                resolvedClientIdAndSecret.getBytes(StandardCharsets.UTF_8));

        List<String> scopes = record.scopes();
        String form = "grant_type=client_credentials"
                + (scopes.isEmpty() ? "" : "&scope=" + URLEncoder.encode(String.join(" ", scopes), StandardCharsets.UTF_8));

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(record.tokenEndpoint()))
                    .header("Authorization", "Basic " + basicAuth)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            Instant requestedAt = clock.instant();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new RouterException("Token request failed for payerId=" + record.payerId()
                        + " status=" + response.statusCode() + " body=" + response.body());
            }

            JsonNode json = mapper.readTree(response.body());
            JsonNode accessToken = json.get("access_token");
            if (accessToken == null) {
                throw new RouterException("Token response for payerId=" + record.payerId()
                        + " had no access_token field");
            }

            // Measure expiry from when the request was sent, not when it returned.
            JsonNode expiresIn = json.get("expires_in");
            Instant refreshAt = null;
            if (expiresIn != null && expiresIn.canConvertToLong() && expiresIn.asLong() > 0) {
                refreshAt = requestedAt.plusSeconds(expiresIn.asLong()).minus(EXPIRY_SKEW);
            }
            return new CachedToken(accessToken.asText(), refreshAt);
        } catch (IOException e) {
            throw new RouterException("Token request I/O failure for payerId=" + record.payerId(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RouterException("Token request interrupted for payerId=" + record.payerId(), e);
        }
    }

    private static CacheKey cacheKey(ConnectionRecord record, String resolvedClientIdAndSecret) {
        int sep = resolvedClientIdAndSecret.indexOf(':');
        if (sep < 0) {
            throw new RouterException(
                    "OAUTH2_CLIENT_CREDENTIALS secret for payerId=" + record.payerId()
                            + " must be stored as \"clientId:clientSecret\"");
        }
        // tokenEndpoint presence is already enforced by ConnectionRecord for this authType.
        // Key on client ID, never the secret, so secrets don't linger as map keys.
        return new CacheKey(record.tokenEndpoint(), resolvedClientIdAndSecret.substring(0, sep), List.copyOf(record.scopes()));
    }

    private record CacheKey(String tokenEndpoint, String clientId, List<String> scopes) { }

    private record CachedToken(String accessToken, Instant refreshAt) { }
}
