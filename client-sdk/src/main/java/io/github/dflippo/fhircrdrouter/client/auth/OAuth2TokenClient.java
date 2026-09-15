package io.github.dflippo.fhircrdrouter.client.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippo.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippo.fhircrdrouter.core.RouterException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Minimal OAuth2 client-credentials token fetch for
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
 * <p>No token caching/retry yet — every call fetches a fresh token. Fine for
 * examples/low-volume use; add caching before any real production use.
 */
public final class OAuth2TokenClient {

    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    public OAuth2TokenClient(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public String fetchAccessToken(ConnectionRecord record, String resolvedClientIdAndSecret) {
        int sep = resolvedClientIdAndSecret.indexOf(':');
        if (sep < 0) {
            throw new RouterException(
                    "OAUTH2_CLIENT_CREDENTIALS secret for payerId=" + record.payerId()
                            + " must be stored as \"clientId:clientSecret\"");
        }
        String basicAuth = Base64.getEncoder().encodeToString(
                resolvedClientIdAndSecret.getBytes(StandardCharsets.UTF_8));

        List<String> scopes = record.scopes();
        String form = "grant_type=client_credentials"
                + (scopes.isEmpty() ? "" : "&scope=" + urlEncode(String.join(" ", scopes)));

        try {
            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(record.tokenEndpoint()))
                    .header("Authorization", "Basic " + basicAuth)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() / 100 != 2) {
                throw new RouterException("Token request failed for payerId=" + record.payerId()
                        + " status=" + response.statusCode() + " body=" + response.body());
            }

            JsonNode json = mapper.readTree(response.body());
            JsonNode accessToken = json.get("access_token");
            if (accessToken == null) {
                throw new RouterException("Token response for payerId=" + record.payerId()
                        + " had no access_token field: " + response.body());
            }
            return accessToken.asText();
        } catch (IOException e) {
            throw new RouterException("Token request I/O failure for payerId=" + record.payerId(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RouterException("Token request interrupted for payerId=" + record.payerId(), e);
        }
    }

    private static String urlEncode(String value) {
        return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
