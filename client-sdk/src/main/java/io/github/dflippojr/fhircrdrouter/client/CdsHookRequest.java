package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;

import java.util.Collections;
import java.util.LinkedHashMap;
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
 * everything its discovery response asks for. A {@code fhirAuthorization}
 * requires a {@code fhirServer}
 * (<a href="https://cds-hooks.hl7.org/2.0/#http-request_1">CDS Hooks 2.0, HTTP Request</a>:
 * "If fhirAuthorization is provided, this field is REQUIRED").
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
        if (fhirAuthorization != null && (fhirServer == null || fhirServer.isBlank())) {
            throw new IllegalArgumentException("fhirServer is required when fhirAuthorization is set");
        }
        if (prefetch == null || prefetch.isEmpty()) {
            prefetch = null;
        } else {
            // Not Map.copyOf: a null value means "no data" and must survive; null keys stay invalid.
            Map<String, Object> copy = new LinkedHashMap<>(prefetch);
            if (copy.containsKey(null)) {
                throw new NullPointerException("prefetch key");
            }
            prefetch = Collections.unmodifiableMap(copy);
        }
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

    /**
     * The CDS Hooks {@code fhirAuthorization} object: an OAuth2 bearer token for {@code fhirServer}.
     * Every field but {@code patient} is required, and {@code token_type} is fixed to {@code Bearer}
     * (<a href="https://cds-hooks.hl7.org/2.0/#passing-the-access-token-to-the-cds-service">CDS Hooks 2.0,
     * Passing the Access Token to the CDS Service</a>). A null {@code tokenType} means {@code Bearer}.
     * Send {@code patient}, the FHIR id the token is restricted to, when {@code scope} has
     * {@code patient/} scopes.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FhirAuthorization(
            @JsonProperty("access_token") String accessToken,
            @JsonProperty("token_type") String tokenType,
            @JsonProperty("expires_in") Integer expiresIn,
            @JsonProperty("scope") String scope,
            @JsonProperty("subject") String subject,
            @JsonProperty("patient") String patient
    ) {
        public FhirAuthorization {
            required(accessToken, "accessToken");
            tokenType = tokenType == null ? "Bearer" : tokenType;
            if (!"Bearer".equals(tokenType)) {
                throw new IllegalArgumentException("tokenType must be Bearer");
            }
            if (expiresIn == null) {
                throw new IllegalArgumentException("expiresIn is required");
            }
            required(scope, "scope");
            required(subject, "subject");
        }

        /** A token with no {@code patient} restriction. */
        public FhirAuthorization(String accessToken, String tokenType, Integer expiresIn, String scope,
                                 String subject) {
            this(accessToken, tokenType, expiresIn, scope, subject, null);
        }

        private static void required(String value, String name) {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException(name + " is required");
            }
        }
    }
}
