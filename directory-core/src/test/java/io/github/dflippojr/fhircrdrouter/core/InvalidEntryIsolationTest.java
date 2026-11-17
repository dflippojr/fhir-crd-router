package io.github.dflippojr.fhircrdrouter.core;

import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * #231: one stored entry that this version cannot bind must not break the store for every other payer.
 * Each {@link Bad} case puts one such entry next to a valid {@code PAYER-OK} entry. The bad entries carry
 * sentinel values, so a test can check that no field value leaks into an error message.
 */
class InvalidEntryIsolationTest {

    static final String OK_ENTRY = """
            - payerId: "PAYER-OK"
              environment: "PRODUCTION"
              baseUrl: "https://ok.example/r4"
              authType: "NONE"
            """;

    /** Values that must never appear in an error message or its cause chain. */
    static final List<String> SENTINELS = List.of(
            "sentinel-base.example", "SENTINEL-CLIENT", "sentinel-token.example", "SENTINEL-KEY",
            "SENTINEL-UNKNOWN-VALUE", "FUTURE_AUTH_SENTINEL", "FUTURE_ENV_SENTINEL", "FUTURE_STATUS_SENTINEL");

    /** One entry per way an entry can fail to bind today (#231, "Problem"). */
    enum Bad {
        OAUTH2_MISSING_CLIENT_ID("IllegalArgumentException", true, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "OAUTH2_CLIENT_CREDENTIALS"
                  tokenEndpoint: "https://sentinel-token.example/token"
                """),
        JWT_MISSING_KEY_ID("IllegalArgumentException", true, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "CDS_HOOKS_JWT"
                  clientId: "SENTINEL-CLIENT"
                """),
        UNKNOWN_PROPERTY("UnrecognizedPropertyException", true, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "NONE"
                  futureField: "SENTINEL-UNKNOWN-VALUE"
                """),
        UNKNOWN_AUTH_TYPE("InvalidFormatException", true, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "FUTURE_AUTH_SENTINEL"
                  clientId: "SENTINEL-CLIENT"
                  keyId: "SENTINEL-KEY"
                """),
        /** An unknown environment leaves the entry with no key this version can name. */
        UNKNOWN_ENVIRONMENT("InvalidFormatException", false, """
                - payerId: "PAYER-BAD"
                  environment: "FUTURE_ENV_SENTINEL"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "NONE"
                """),
        UNKNOWN_STATUS("InvalidFormatException", true, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "NONE"
                  status: "FUTURE_STATUS_SENTINEL"
                """);

        final String problem;
        final boolean keyed;
        final String yaml;

        Bad(String problem, boolean keyed, String yaml) {
            this.problem = problem;
            this.keyed = keyed;
            this.yaml = yaml;
        }
    }

    static Path storeWith(Path dir, Bad bad) throws Exception {
        Path file = dir.resolve("connections.yaml");
        // The bad entry first, so a reader that stops at the first failure never reaches PAYER-OK.
        Files.writeString(file, bad.yaml + OK_ENTRY);
        return file;
    }

    @ParameterizedTest
    @EnumSource(Bad.class)
    void anotherPayerStillResolves(Bad bad, @TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, bad));

        assertEquals("https://ok.example/r4", new PayerRouter(store).resolve("PAYER-OK", Environment.PRODUCTION).baseUrl());
        assertTrue(store.findByPayerIdAndEnvironment("PAYER-OK", Environment.PRODUCTION).isPresent());
        assertEquals(List.of("PAYER-OK"), store.findByPayerId("PAYER-OK").stream().map(ConnectionRecord::payerId).toList());
        assertEquals(List.of("PAYER-OK"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
    }

    @ParameterizedTest
    @EnumSource(value = Bad.class, mode = EnumSource.Mode.EXCLUDE, names = "UNKNOWN_ENVIRONMENT")
    void theInvalidEntrysOwnKeyThrowsANamedError(Bad bad, @TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, bad));

        RouterException e = assertThrows(RouterException.class,
                () -> new PayerRouter(store).resolve("PAYER-BAD", Environment.PRODUCTION));

        String message = e.getMessage();
        assertTrue(message.contains("payerId=PAYER-BAD"), message);
        assertTrue(message.contains("environment=PRODUCTION"), message);
        assertTrue(message.contains(bad.problem), message);
        // A broken record must not read as merely absent.
        assertFalse(message.startsWith("No active connection"), message);
        assertNoSentinel(e);
    }

    @ParameterizedTest
    @EnumSource(Bad.class)
    void findByPayerIdOfTheInvalidPayerThrows(Bad bad, @TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, bad));

        RouterException e = assertThrows(RouterException.class, () -> store.findByPayerId("PAYER-BAD"));

        assertTrue(e.getMessage().contains("payerId=PAYER-BAD"), e.getMessage());
        assertTrue(e.getMessage().contains(bad.problem), e.getMessage());
        assertNoSentinel(e);
    }

    @ParameterizedTest
    @EnumSource(value = Bad.class, names = "UNKNOWN_ENVIRONMENT")
    void anEntryWithAnUnknownEnvironmentMatchesNoKnownEnvironment(Bad bad, @TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, bad));

        for (Environment environment : Environment.values()) {
            assertTrue(store.findByPayerIdAndEnvironment("PAYER-BAD", environment).isEmpty());
        }
    }

    static void assertNoSentinel(Throwable thrown) {
        for (Throwable t = thrown; t != null; t = t.getCause()) {
            String text = String.valueOf(t.getMessage());
            for (String sentinel : SENTINELS) {
                assertFalse(text.contains(sentinel), "leaked " + sentinel + " in " + t);
            }
        }
    }
}
