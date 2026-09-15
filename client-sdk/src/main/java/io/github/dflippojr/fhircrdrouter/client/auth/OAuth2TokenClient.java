package io.github.dflippojr.fhircrdrouter.client.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.util.concurrent.ConcurrentHashMap;

/**
 * OAuth2 client-credentials token fetch for
 * {@code authType = OAUTH2_CLIENT_CREDENTIALS} connections.
 *
 * <p>Follows RFC 6749: the client ID is a non-secret identifier stored on
 * the record ({@link ConnectionRecord#clientId()}), and only the client
 * secret lives behind {@code credentialRef}. The pair is sent with the
 * {@code client_secret_basic} method (HTTP Basic, each part form-urlencoded
 * first per §2.3.1), which authorization servers are required to support.
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
    public String fetchAccessToken(ConnectionRecord record, String clientSecret) {
        CacheKey key = cacheKey(record);
        CachedToken cached = cache.get(key);
        if (cached != null && clock.instant().isBefore(cached.refreshAt())) {
            return cached.accessToken();
        }
        CachedToken fresh = requestToken(record, clientSecret);
        if (fresh.refreshAt() != null) {
            cache.put(key, fresh);
        } else {
            cache.remove(key);
        }
        return fresh.accessToken();
    }

    /** Drops any cached token for this connection, e.g. after the payer returns 401. */
    public void invalidate(ConnectionRecord record) {
        cache.remove(cacheKey(record));
    }

    private CachedToken requestToken(ConnectionRecord record, String clientSecret) {
        String credentials = formEncode(record.clientId()) + ":" + formEncode(clientSecret);
        String basicAuth = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));

        List<String> scopes = record.scopes();
        String form = "grant_type=client_credentials"
                + (scopes.isEmpty() ? "" : "&scope=" + formEncode(String.join(" ", scopes)));

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

    // tokenEndpoint and clientId presence are already enforced by ConnectionRecord for this authType.
    private static CacheKey cacheKey(ConnectionRecord record) {
        return new CacheKey(record.tokenEndpoint(), record.clientId(), record.scopes());
    }

    private static String formEncode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private record CacheKey(String tokenEndpoint, String clientId, List<String> scopes) { }

    private record CachedToken(String accessToken, Instant refreshAt) { }
}
