package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.time.Instant;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ConnectionRecordTest {

    private static final List<String> FIELDS = List.of("tokenEndpoint", "clientId", "keyId");

    /**
     * Which of tokenEndpoint, clientId and keyId each auth type requires, in the order the constructor checks
     * them. Every AuthType needs a row: {@link #everyAuthTypeIsListed} fails until a new constant is decided here.
     */
    private static final Map<AuthType, List<String>> REQUIRED = Map.of(
            AuthType.NONE, List.of(),
            AuthType.API_KEY, List.of(),
            AuthType.OAUTH2_CLIENT_CREDENTIALS, List.of("tokenEndpoint", "clientId"),
            AuthType.OAUTH2_PRIVATE_KEY_JWT, List.of("tokenEndpoint", "clientId", "keyId"),
            AuthType.CDS_HOOKS_JWT, List.of("clientId", "keyId"));

    @Test
    void everyAuthTypeIsListed() {
        assertEquals(EnumSet.allOf(AuthType.class), REQUIRED.keySet());
    }

    @ParameterizedTest
    @MethodSource("authTypeAndField")
    void refusesABlankFieldExactlyWhenTheAuthTypeRequiresIt(AuthType authType, String field) {
        ConnectionRecord.Builder builder = withFields(authType,
                FIELDS.stream().filter(f -> !f.equals(field)).toList());

        if (REQUIRED.get(authType).contains(field)) {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, builder::build);
            assertTrue(e.getMessage().startsWith(field + " is required"), e.getMessage());
        } else {
            assertDoesNotThrow(builder::build);
        }
    }

    @ParameterizedTest
    @EnumSource(AuthType.class)
    void reportsTheFirstMissingFieldInCheckOrder(AuthType authType) {
        List<String> required = REQUIRED.get(authType);
        if (required.isEmpty()) {
            assertDoesNotThrow(withFields(authType, List.of())::build);
        }
        for (int present = 0; present < required.size(); present++) {
            ConnectionRecord.Builder builder = withFields(authType, required.subList(0, present));
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, builder::build);
            assertTrue(e.getMessage().startsWith(required.get(present) + " is required"), e.getMessage());
        }
    }

    static Stream<Arguments> authTypeAndField() {
        return Arrays.stream(AuthType.values())
                .flatMap(authType -> FIELDS.stream().map(field -> Arguments.of(authType, field)));
    }

    @Test
    void jwtAuthTypesRequireClientIdAndKeyId() {
        assertThrows(IllegalArgumentException.class, () -> base(AuthType.CDS_HOOKS_JWT).keyId("k").build());
        IllegalArgumentException missingKey = assertThrows(IllegalArgumentException.class,
                () -> base(AuthType.CDS_HOOKS_JWT).clientId("iss").build());
        assertTrue(missingKey.getMessage().contains("keyId"));
        assertDoesNotThrow(() -> base(AuthType.CDS_HOOKS_JWT).clientId("iss").keyId("k").build());

        assertThrows(IllegalArgumentException.class, () -> base(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                .clientId("c").keyId("k").build(), "tokenEndpoint required");
        assertDoesNotThrow(() -> base(AuthType.OAUTH2_PRIVATE_KEY_JWT)
                .clientId("c").keyId("k").tokenEndpoint("https://payer.test/token").build());
    }

    @Test
    void mutualTlsCombinesWithAnyAuthType() {
        assertDoesNotThrow(() -> base(AuthType.NONE).mtlsCredentialRef("cert").build());
        assertDoesNotThrow(() -> base(AuthType.OAUTH2_CLIENT_CREDENTIALS).mtlsCredentialRef("cert")
                .tokenEndpoint("https://payer.test/token").clientId("c").build());
    }

    @Test
    void withLastVerifiedAtChangesOnlyThatField() {
        ConnectionRecord original = base(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .displayName("Synthetic").tokenEndpoint("https://payer.test/token").clientId("c")
                .scopes(List.of("system/*.read")).credentialRef("ref").mtlsCredentialRef("cert")
                .igVersion("2.1.0").status(ConnectionStatus.INACTIVE).contactInfo("ops@payer.test")
                .createdAt(Instant.EPOCH).updatedAt(Instant.EPOCH.plusSeconds(60)).build();
        Instant verifiedAt = Instant.parse("2026-10-13T12:00:00Z");

        ConnectionRecord verified = original.withLastVerifiedAt(verifiedAt);

        assertEquals(verifiedAt, verified.lastVerifiedAt());
        assertEquals(Instant.EPOCH.plusSeconds(60), verified.updatedAt());
        assertNull(original.lastVerifiedAt());
        // Every other component is equal: clearing the field again restores the original.
        assertEquals(original, verified.withLastVerifiedAt(null));
    }

    private static ConnectionRecord.Builder base(AuthType authType) {
        return ConnectionRecord.builder()
                .payerId("PAYER-AUTH")
                .environment(Environment.SANDBOX)
                .baseUrl("https://payer.test/cds")
                .authType(authType);
    }

    /** {@link #base} with only the named fields set; the others stay null. */
    private static ConnectionRecord.Builder withFields(AuthType authType, List<String> present) {
        ConnectionRecord.Builder builder = base(authType);
        for (String field : present) {
            builder = switch (field) {
                case "tokenEndpoint" -> builder.tokenEndpoint("https://payer.test/token");
                case "clientId" -> builder.clientId("client");
                case "keyId" -> builder.keyId("k1");
                default -> throw new IllegalArgumentException(field);
            };
        }
        return builder;
    }
}
