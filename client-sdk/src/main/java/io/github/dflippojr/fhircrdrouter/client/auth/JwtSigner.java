package io.github.dflippojr.fhircrdrouter.client.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.RouterException;

import java.net.URI;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Signs the two kinds of short-lived authentication JWT this SDK sends:
 * the CDS Hooks 2.0 client JWT and the OAuth2 {@code private_key_jwt}
 * client assertion (SMART Backend Services).
 *
 * <p>The algorithm follows the key: RSA (2048+ bits) signs with RS384 and
 * EC P-384 with ES384, the two algorithms both specs recommend. Other curves
 * are rejected rather than silently picking an algorithm a payer may not accept.
 */
public final class JwtSigner {

    /** Both specs expect these JWTs to live no more than five minutes. */
    public static final Duration LIFETIME = Duration.ofMinutes(5);

    static final String CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    private final Clock clock;

    public JwtSigner() {
        this(Clock.systemUTC());
    }

    JwtSigner(Clock clock) {
        this.clock = clock;
    }

    /**
     * CDS Hooks client JWT for one request: {@code iss} = clientId,
     * {@code aud} = the exact service URL being called, plus {@code tenant} when set.
     */
    public String cdsHooksJwt(ConnectionRecord record, PrivateKey key, URI serviceUrl) {
        JWTClaimsSet.Builder claims = baseClaims(record)
                .audience(serviceUrl.toString());
        if (record.tenant() != null) {
            claims.claim("tenant", record.tenant());
        }
        return sign(record, key, claims.build());
    }

    /** OAuth2 client assertion: {@code iss} = {@code sub} = clientId, {@code aud} = the token endpoint. */
    public String clientAssertion(ConnectionRecord record, PrivateKey key) {
        return sign(record, key, baseClaims(record)
                .subject(record.clientId())
                .audience(record.tokenEndpoint())
                .build());
    }

    private JWTClaimsSet.Builder baseClaims(ConnectionRecord record) {
        Instant now = clock.instant();
        return new JWTClaimsSet.Builder()
                .issuer(record.clientId())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(now.plus(LIFETIME)))
                .jwtID(UUID.randomUUID().toString());
    }

    private static String sign(ConnectionRecord record, PrivateKey key, JWTClaimsSet claims) {
        try {
            JWSSigner signer;
            JWSAlgorithm algorithm;
            if (key instanceof RSAPrivateKey rsa) {
                if (rsa.getModulus().bitLength() < 2048) {
                    throw new RouterException("RSA signing key for payerId=" + record.payerId()
                            + " must be at least 2048 bits");
                }
                signer = new RSASSASigner(rsa);
                algorithm = JWSAlgorithm.RS384;
            } else if (key instanceof ECPrivateKey ec) {
                if (!Curve.P_384.equals(Curve.forECParameterSpec(ec.getParams()))) {
                    throw new RouterException("EC signing key for payerId=" + record.payerId()
                            + " must use curve P-384 (ES384)");
                }
                signer = new ECDSASigner(ec);
                algorithm = JWSAlgorithm.ES384;
            } else {
                throw new RouterException("Unsupported signing key type " + key.getAlgorithm()
                        + " for payerId=" + record.payerId());
            }

            JWSHeader.Builder header = new JWSHeader.Builder(algorithm)
                    .type(JOSEObjectType.JWT)
                    .keyID(record.keyId());
            if (record.jwksUrl() != null) {
                header.jwkURL(URI.create(record.jwksUrl()));
            }
            SignedJWT jwt = new SignedJWT(header.build(), claims);
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new RouterException("Failed to sign JWT for payerId=" + record.payerId(), e);
        }
    }
}
