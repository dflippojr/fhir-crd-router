package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A payer's FHIR CRD (CDS Hooks) endpoint, plus enough metadata to reach and
 * authenticate against it. Never holds secret material directly — see
 * {@link #credentialRef()} and {@link CredentialProvider}.
 *
 * @param clientId OAuth2 client ID, or the {@code iss} claim for {@link AuthType#CDS_HOOKS_JWT}
 * @param keyId {@code kid} of the signing key, for the JWT-based auth types
 * @param jwksUrl optional {@code jku}: where the payer can fetch your public JWK Set
 * @param tenant optional CDS Hooks {@code tenant} claim identifying the calling organization
 * @param credentialRef the app-layer secret: API key, client secret, or PEM private key
 * @param mtlsCredentialRef optional; when set, connections use mutual TLS with the PEM
 *     client certificate chain and private key this resolves to. Works with any {@link AuthType}.
 */
public record ConnectionRecord(
        String payerId,
        String displayName,
        Environment environment,
        String baseUrl,
        AuthType authType,
        String tokenEndpoint,
        String clientId,
        String keyId,
        String jwksUrl,
        String tenant,
        List<String> scopes,
        String credentialRef,
        String mtlsCredentialRef,
        String igVersion,
        ConnectionStatus status,
        Instant lastVerifiedAt,
        String contactInfo,
        Instant createdAt,
        Instant updatedAt
) {
    @JsonCreator
    public ConnectionRecord(
            @JsonProperty("payerId") String payerId,
            @JsonProperty("displayName") String displayName,
            @JsonProperty("environment") Environment environment,
            @JsonProperty("baseUrl") String baseUrl,
            @JsonProperty("authType") AuthType authType,
            @JsonProperty("tokenEndpoint") String tokenEndpoint,
            @JsonProperty("clientId") String clientId,
            @JsonProperty("keyId") String keyId,
            @JsonProperty("jwksUrl") String jwksUrl,
            @JsonProperty("tenant") String tenant,
            @JsonProperty("scopes") List<String> scopes,
            @JsonProperty("credentialRef") String credentialRef,
            @JsonProperty("mtlsCredentialRef") String mtlsCredentialRef,
            @JsonProperty("igVersion") String igVersion,
            @JsonProperty("status") ConnectionStatus status,
            @JsonProperty("lastVerifiedAt") Instant lastVerifiedAt,
            @JsonProperty("contactInfo") String contactInfo,
            @JsonProperty("createdAt") Instant createdAt,
            @JsonProperty("updatedAt") Instant updatedAt
    ) {
        this.payerId = Objects.requireNonNull(payerId, "payerId");
        this.displayName = displayName;
        this.environment = Objects.requireNonNull(environment, "environment");
        this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl");
        this.authType = Objects.requireNonNull(authType, "authType");
        this.tokenEndpoint = tokenEndpoint;
        this.clientId = clientId;
        this.keyId = keyId;
        this.jwksUrl = jwksUrl;
        this.tenant = tenant;
        this.scopes = scopes == null ? List.of() : List.copyOf(scopes);
        this.credentialRef = credentialRef;
        this.mtlsCredentialRef = mtlsCredentialRef;
        this.igVersion = igVersion;
        this.status = status == null ? ConnectionStatus.ACTIVE : status;
        this.lastVerifiedAt = lastVerifiedAt;
        this.contactInfo = contactInfo;
        this.createdAt = createdAt == null ? Instant.now() : createdAt;
        this.updatedAt = updatedAt == null ? Instant.now() : updatedAt;

        boolean oauth2 = authType == AuthType.OAUTH2_CLIENT_CREDENTIALS || authType == AuthType.OAUTH2_PRIVATE_KEY_JWT;
        boolean signsJwt = authType == AuthType.OAUTH2_PRIVATE_KEY_JWT || authType == AuthType.CDS_HOOKS_JWT;
        if (oauth2) {
            requireForAuthType(tokenEndpoint, "tokenEndpoint");
        }
        if (oauth2 || signsJwt) {
            requireForAuthType(clientId, "clientId");
        }
        if (signsJwt) {
            requireForAuthType(keyId, "keyId");
        }
    }

    private void requireForAuthType(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    field + " is required when authType = " + authType + " (payerId=" + payerId + ")");
        }
    }

    /** Composite identity: a payer can have one record per environment. */
    public String key() {
        return payerId + ":" + environment;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Fluent builder — {@link ConnectionRecord} itself stays a plain immutable record. */
    public static final class Builder {
        private String payerId;
        private String displayName;
        private Environment environment;
        private String baseUrl;
        private AuthType authType = AuthType.NONE;
        private String tokenEndpoint;
        private String clientId;
        private String keyId;
        private String jwksUrl;
        private String tenant;
        private String mtlsCredentialRef;
        private List<String> scopes = List.of();
        private String credentialRef;
        private String igVersion;
        private ConnectionStatus status = ConnectionStatus.ACTIVE;
        private Instant lastVerifiedAt;
        private String contactInfo;
        private Instant createdAt;
        private Instant updatedAt;

        public Builder payerId(String v) { this.payerId = v; return this; }
        public Builder displayName(String v) { this.displayName = v; return this; }
        public Builder environment(Environment v) { this.environment = v; return this; }
        public Builder baseUrl(String v) { this.baseUrl = v; return this; }
        public Builder authType(AuthType v) { this.authType = v; return this; }
        public Builder tokenEndpoint(String v) { this.tokenEndpoint = v; return this; }
        public Builder clientId(String v) { this.clientId = v; return this; }
        public Builder keyId(String v) { this.keyId = v; return this; }
        public Builder jwksUrl(String v) { this.jwksUrl = v; return this; }
        public Builder tenant(String v) { this.tenant = v; return this; }
        public Builder mtlsCredentialRef(String v) { this.mtlsCredentialRef = v; return this; }
        public Builder scopes(List<String> v) { this.scopes = v; return this; }
        public Builder credentialRef(String v) { this.credentialRef = v; return this; }
        public Builder igVersion(String v) { this.igVersion = v; return this; }
        public Builder status(ConnectionStatus v) { this.status = v; return this; }
        public Builder lastVerifiedAt(Instant v) { this.lastVerifiedAt = v; return this; }
        public Builder contactInfo(String v) { this.contactInfo = v; return this; }
        public Builder createdAt(Instant v) { this.createdAt = v; return this; }
        public Builder updatedAt(Instant v) { this.updatedAt = v; return this; }

        public ConnectionRecord build() {
            return new ConnectionRecord(payerId, displayName, environment, baseUrl, authType,
                    tokenEndpoint, clientId, keyId, jwksUrl, tenant, scopes, credentialRef, mtlsCredentialRef, igVersion, status, lastVerifiedAt,
                    contactInfo, createdAt, updatedAt);
        }
    }
}
