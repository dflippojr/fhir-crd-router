package io.github.dflippojr.fhircrdrouter.client.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.github.dflippojr.fhircrdrouter.client.testsupport.TestKeys;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import io.github.dflippojr.fhircrdrouter.core.RouterException;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JwtSignerTest {

    private static final Instant NOW = Instant.parse("2026-09-15T12:00:00Z");
    private static final URI SERVICE = URI.create("https://payer.example/cds-services/order-sign-crd");

    private final JwtSigner signer = new JwtSigner(Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void cdsHooksJwtWithEs384HasRequiredHeaderAndClaims() throws Exception {
        KeyPair keys = TestKeys.ec("secp384r1");
        ConnectionRecord record = record(AuthType.CDS_HOOKS_JWT, "https://ehr.example/cds-client", "tenant-7");

        SignedJWT jwt = SignedJWT.parse(signer.cdsHooksJwt(record, keys.getPrivate(), SERVICE));

        assertTrue(jwt.verify(new ECDSAVerifier((ECPublicKey) keys.getPublic())));
        assertEquals(JWSAlgorithm.ES384, jwt.getHeader().getAlgorithm());
        assertEquals("JWT", jwt.getHeader().getType().getType());
        assertEquals("key-1", jwt.getHeader().getKeyID());
        assertEquals(URI.create("https://ehr.example/.well-known/jwks.json"), jwt.getHeader().getJWKURL());

        var claims = jwt.getJWTClaimsSet();
        assertEquals("https://ehr.example/cds-client", claims.getIssuer());
        assertEquals(List.of(SERVICE.toString()), claims.getAudience());
        assertEquals(NOW.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
        assertEquals(300, claims.getExpirationTime().toInstant().getEpochSecond() - NOW.getEpochSecond());
        assertFalse(claims.getJWTID().isBlank());
        assertEquals("tenant-7", claims.getStringClaim("tenant"));
        assertNull(claims.getSubject());
    }

    @Test
    void eachJwtGetsAFreshJti() throws Exception {
        KeyPair keys = TestKeys.ec("secp384r1");
        ConnectionRecord record = record(AuthType.CDS_HOOKS_JWT, "iss", null);

        String first = SignedJWT.parse(signer.cdsHooksJwt(record, keys.getPrivate(), SERVICE)).getJWTClaimsSet().getJWTID();
        String second = SignedJWT.parse(signer.cdsHooksJwt(record, keys.getPrivate(), SERVICE)).getJWTClaimsSet().getJWTID();

        assertNotEquals(first, second);
    }

    @Test
    void clientAssertionWithRs384() throws Exception {
        KeyPair keys = TestKeys.rsa(2048);
        ConnectionRecord record = record(AuthType.OAUTH2_PRIVATE_KEY_JWT, "client-123", null);

        SignedJWT jwt = SignedJWT.parse(signer.clientAssertion(record, keys.getPrivate()));
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keys.getPublic());

        assertTrue(jwt.verify(verifier));
        assertEquals(JWSAlgorithm.RS384, jwt.getHeader().getAlgorithm());
        assertEquals("client-123", jwt.getJWTClaimsSet().getIssuer());
        assertEquals("client-123", jwt.getJWTClaimsSet().getSubject());
        assertEquals(List.of("https://payer.example/token"), jwt.getJWTClaimsSet().getAudience());
    }

    @Test
    void rejectsKeysOutsideRecommendedAlgorithms() {
        ConnectionRecord record = record(AuthType.CDS_HOOKS_JWT, "iss", null);

        assertThrows(RouterException.class,
                () -> signer.cdsHooksJwt(record, TestKeys.ec("secp256r1").getPrivate(), SERVICE));
        assertThrows(RouterException.class,
                () -> signer.cdsHooksJwt(record, TestKeys.rsa(1024).getPrivate(), SERVICE));
    }

    @Test
    void jwksPublishesPublicPartsOnly() throws Exception {
        KeyPair ec = TestKeys.ec("secp384r1");
        KeyPair rsa = TestKeys.rsa(2048);

        JsonNode jwks = new ObjectMapper().readTree(Jwks.builder()
                .add("ec-1", PemKeys.readPublicKey(PemKeys.toPem("PUBLIC KEY", ec.getPublic().getEncoded())))
                .add("rsa-1", rsa.getPublic())
                .toJson());

        assertEquals(2, jwks.get("keys").size());
        assertEquals("ES384", jwks.at("/keys/0/alg").asText());
        assertEquals("P-384", jwks.at("/keys/0/crv").asText());
        assertEquals("RS384", jwks.at("/keys/1/alg").asText());
        assertEquals("sig", jwks.at("/keys/1/use").asText());
        jwks.get("keys").forEach(key -> assertFalse(key.has("d"), "private exponent must not be published"));
        assertThrows(IllegalArgumentException.class,
                () -> Jwks.builder().add("p256", TestKeys.ec("secp256r1").getPublic()));
    }

    @Test
    void pemKeysReadsPkcs8AndExplainsPkcs1() {
        KeyPair ec = TestKeys.ec("secp384r1");
        assertEquals(ec.getPrivate(), PemKeys.readPrivateKey(TestKeys.privateKeyPem(ec)));

        IllegalArgumentException error = assertThrows(IllegalArgumentException.class,
                () -> PemKeys.readPrivateKey("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----"));
        assertTrue(error.getMessage().contains("openssl pkcs8"));
    }

    private static ConnectionRecord record(AuthType authType, String clientId, String tenant) {
        return ConnectionRecord.builder()
                .payerId("PAYER-JWT")
                .environment(Environment.SANDBOX)
                .baseUrl("https://payer.example")
                .authType(authType)
                .tokenEndpoint("https://payer.example/token")
                .clientId(clientId)
                .keyId("key-1")
                .jwksUrl("https://ehr.example/.well-known/jwks.json")
                .tenant(tenant)
                .credentialRef("signing-key")
                .build();
    }
}
