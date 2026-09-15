package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;

import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * A CDS Hooks invocation request. For CRD hooks, prefer
 * {@link #of(CrdHookContext, Map)}, which fills in the hook name and a fresh
 * {@code hookInstance} from a typed context.
 *
 * <p>{@code fhirServer} and {@code fhirAuthorization} are optional: without
 * them the payer can only use what is sent in {@code prefetch}, so send
 * everything its discovery response asks for.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CdsHookRequest(
        String hook,
        String hookInstance,
        String fhirServer,
        FhirAuthorization fhirAuthorization,
        Object context,
        Map<String, Object> prefetch
) {
    public CdsHookRequest {
        Objects.requireNonNull(hook, "hook");
        Objects.requireNonNull(hookInstance, "hookInstance");
        Objects.requireNonNull(context, "context");
        prefetch = prefetch == null || prefetch.isEmpty() ? null : Map.copyOf(prefetch);
    }

    /** Untyped form, for hooks or context shapes this library doesn't model. */
    public CdsHookRequest(String hook, String hookInstance, Map<String, Object> context, Map<String, Object> prefetch) {
        this(hook, hookInstance, null, null, context, prefetch);
    }

    /** Typed CRD request with a random {@code hookInstance} and no FHIR server access. */
    public static CdsHookRequest of(CrdHookContext context, Map<String, Object> prefetch) {
        return new CdsHookRequest(context.hook(), UUID.randomUUID().toString(), null, null, context, prefetch);
    }

    /** Returns a copy that grants the payer access to the EHR's FHIR server. */
    public CdsHookRequest withFhirServer(String fhirServer, FhirAuthorization fhirAuthorization) {
        return new CdsHookRequest(hook, hookInstance, fhirServer, fhirAuthorization, context, prefetch);
    }

    /** The CDS Hooks {@code fhirAuthorization} object (an OAuth2 bearer token for {@code fhirServer}). */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FhirAuthorization(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") Integer expiresIn,
            @JsonProperty("scope") String scope,
            @JsonProperty("subject") String subject
    ) {
        public FhirAuthorization {
            Objects.requireNonNull(accessToken, "accessToken");
            tokenType = tokenType == null ? "Bearer" : tokenType;
        }
    }
}
