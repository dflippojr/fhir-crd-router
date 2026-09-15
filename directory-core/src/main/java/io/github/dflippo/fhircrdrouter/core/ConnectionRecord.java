package io.github.dflippo.fhircrdrouter.core;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * A payer's FHIR CRD (CDS Hooks) endpoint, plus enough metadata to reach and
 * authenticate against it. Never holds secret material directly — see
 * {@link #credentialRef()} and {@link CredentialProvider}.
 */
public record ConnectionRecord(
        String payerId,
        String displayName,
        Environment environment,
        String baseUrl,
        AuthType authType,
        String tokenEndpoint,
        List<String> scopes,
        String credentialRef,
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
            @JsonProperty("scopes") List<String> scopes,
            @JsonProperty("credentialRef") String credentialRef,
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
        this.scopes = scopes == null ? List.of() : List.copyOf(scopes);
        this.credentialRef = credentialRef;
        this.igVersion = igVersion;
        this.status = status == null ? ConnectionStatus.ACTIVE : status;
        this.lastVerifiedAt = lastVerifiedAt;
        this.contactInfo = contactInfo;
        this.createdAt = createdAt == null ? Instant.now() : createdAt;
        this.updatedAt = updatedAt == null ? Instant.now() : updatedAt;

        if (authType == AuthType.OAUTH2_CLIENT_CREDENTIALS && (tokenEndpoint == null || tokenEndpoint.isBlank())) {
            throw new IllegalArgumentException(
                    "tokenEndpoint is required when authType = OAUTH2_CLIENT_CREDENTIALS (payerId=" + payerId + ")");
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
                    tokenEndpoint, scopes, credentialRef, igVersion, status, lastVerifiedAt,
                    contactInfo, createdAt, updatedAt);
        }
    }
}
