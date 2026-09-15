package io.github.dflippo.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippo.fhircrdrouter.client.auth.OAuth2TokenClient;
import io.github.dflippo.fhircrdrouter.core.AuthType;
import io.github.dflippo.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippo.fhircrdrouter.core.CredentialProvider;
import io.github.dflippo.fhircrdrouter.core.RouterException;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

/**
 * Given a resolved {@link ConnectionRecord}, talks to that payer's CDS
 * Hooks endpoint directly — the router itself never does this; only the
 * client SDK does (per the capsule's "optional client SDK" decision).
 */
public final class CdsHooksClient {

    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();
    private final CredentialProvider credentialProvider;
    private final OAuth2TokenClient oauth2TokenClient;

    public CdsHooksClient(CredentialProvider credentialProvider) {
        this(HttpClient.newHttpClient(), credentialProvider);
    }

    public CdsHooksClient(HttpClient httpClient, CredentialProvider credentialProvider) {
        this.httpClient = httpClient;
        this.credentialProvider = credentialProvider;
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

    /** Invokes a named hook and also deserializes the common {@code cards} shape. */
    public CdsHookResponse callHook(ConnectionRecord record, String serviceId, CdsHookRequest request) {
        JsonNode raw = callHookRaw(record, serviceId, request);
        List<Card> cards = new ArrayList<>();
        JsonNode cardsNode = raw.get("cards");
        if (cardsNode != null && cardsNode.isArray()) {
            for (JsonNode node : cardsNode) {
                try {
                    cards.add(mapper.treeToValue(node, Card.class));
                } catch (IOException e) {
                    throw new RouterException("Failed to parse a card in hook response for payerId=" + record.payerId(), e);
                }
            }
        }
        return new CdsHookResponse(cards, raw);
    }

    /**
     * Sends a request with auth applied. For OAuth2 connections a 401 drops the
     * cached token and retries once with a fresh one, since payers can revoke
     * tokens before their advertised expiry.
     */
    private HttpResponse<String> send(ConnectionRecord record, String context, Supplier<HttpRequest.Builder> requestFactory) {
        try {
            HttpResponse<String> response = sendOnce(record, requestFactory);
            if (response.statusCode() == 401 && record.authType() == AuthType.OAUTH2_CLIENT_CREDENTIALS) {
                oauth2TokenClient.invalidate(record, requireSecret(record));
                response = sendOnce(record, requestFactory);
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

    private HttpResponse<String> sendOnce(ConnectionRecord record, Supplier<HttpRequest.Builder> requestFactory)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = requestFactory.get();
        applyAuth(builder, record);
        return httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private void applyAuth(HttpRequest.Builder builder, ConnectionRecord record) {
        switch (record.authType()) {
            case NONE -> { /* no-op */ }
            case API_KEY -> builder.header("Authorization", "Bearer " + requireSecret(record));
            case MUTUAL_TLS -> { /* handled at the HttpClient/SSLContext level, not per-request headers */ }
            case OAUTH2_CLIENT_CREDENTIALS ->
                    builder.header("Authorization", "Bearer " + oauth2TokenClient.fetchAccessToken(record, requireSecret(record)));
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
