package io.github.dflippojr.fhircrdrouter.client.auth;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/**
 * Builds the public JWK Set payers use to verify your JWTs. Host the JSON
 * at the URL you put in {@code jwksUrl} (or hand it to the payer out of
 * band). During key rotation, publish both the old and new keys until
 * nothing signs with the old one.
 *
 * <pre>{@code
 * String json = Jwks.builder()
 *         .add("key-2026-09", PemKeys.readPublicKey(publicKeyPem))
 *         .toJson();
 * }</pre>
 */
public final class Jwks {

    private final List<JWK> keys = new ArrayList<>();

    private Jwks() { }

    public static Jwks builder() {
        return new Jwks();
    }

    /** Adds an RSA (published as RS384) or EC P-384 (ES384) public signing key. */
    public Jwks add(String keyId, PublicKey publicKey) {
        if (publicKey instanceof RSAPublicKey rsa) {
            keys.add(new RSAKey.Builder(rsa).keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS384).build());
        } else if (publicKey instanceof ECPublicKey ec) {
            Curve curve = Curve.forECParameterSpec(ec.getParams());
            if (!Curve.P_384.equals(curve)) {
                throw new IllegalArgumentException("EC key " + keyId + " must use curve P-384, got " + curve);
            }
            keys.add(new ECKey.Builder(curve, ec).keyID(keyId).keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.ES384).build());
        } else {
            throw new IllegalArgumentException("Unsupported public key type " + publicKey.getAlgorithm());
        }
        return this;
    }

    /** The JWK Set JSON, containing public key material only. */
    public String toJson() {
        return new JWKSet(keys).toString(true);
    }
}
