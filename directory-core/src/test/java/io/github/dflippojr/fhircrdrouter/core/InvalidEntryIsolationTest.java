package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
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

    static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    static JsonNode nodes(Path file) throws Exception {
        return YAML.readTree(file.toFile());
    }

    static List<String> baseUrls(List<ConnectionRecord> records) {
        return records.stream().map(r -> r.key() + " " + r.baseUrl()).toList();
    }

    static ConnectionRecord.Builder recordFor(String payerId) {
        return ConnectionRecord.builder().payerId(payerId).environment(Environment.PRODUCTION)
                .baseUrl("https://" + payerId.toLowerCase() + ".example/r4").authType(AuthType.NONE);
    }

    /** Stage 2 of #231: a rewrite keeps every entry it did not touch as it was read, readable or not. */
    @ParameterizedTest
    @EnumSource(Bad.class)
    void saveOfAnotherRecordKeepsTheInvalidEntryAsRead(Bad bad, @TempDir Path dir) throws Exception {
        Path file = storeWith(dir, bad);
        JsonNode before = nodes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-NEW").build());

        JsonNode after = nodes(file);
        assertEquals(3, after.size());
        assertEquals(before.get(0), after.get(0));
        assertEquals(before.get(1), after.get(1));
        assertEquals("PAYER-NEW", after.get(2).get("payerId").asText());
        assertThrows(InvalidConnectionRecordException.class, () -> store.findByPayerId("PAYER-BAD"));
        // The cache the save refreshed answers like a fresh read of the file. PAYER-OK has no stored
        // createdAt, so each read fills it with the time of the read; compare what the file holds.
        assertEquals(baseUrls(new FileBasedConnectionStore(file).findAll()), baseUrls(store.findAll()));
        assertEquals(List.of("PAYER-OK", "PAYER-NEW"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
    }

    @ParameterizedTest
    @EnumSource(Bad.class)
    void deleteOfAnotherRecordKeepsTheInvalidEntryAsRead(Bad bad, @TempDir Path dir) throws Exception {
        Path file = storeWith(dir, bad);
        JsonNode before = nodes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.delete("PAYER-OK", Environment.PRODUCTION);

        JsonNode after = nodes(file);
        assertEquals(1, after.size());
        assertEquals(before.get(0), after.get(0));
        assertEquals(List.of(), store.findAll());
    }

    /** An older writer's update of an entry a newer version wrote keeps the newer field. */
    @Test
    void saveOverAnEntryWithAnUnknownFieldKeepsThatField(@TempDir Path dir) throws Exception {
        Path file = storeWith(dir, Bad.UNKNOWN_PROPERTY);
        JsonNode before = nodes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-BAD").baseUrl("https://updated.example/r4").build());

        JsonNode after = nodes(file);
        assertEquals(2, after.size());
        assertEquals("SENTINEL-UNKNOWN-VALUE", after.get(0).get("futureField").asText());
        assertEquals("https://updated.example/r4", after.get(0).get("baseUrl").asText());
        assertEquals(before.get(1), after.get(1));
        // The field is still one this version does not know, so the entry stays unreadable here.
        InvalidConnectionRecordException e = assertThrows(InvalidConnectionRecordException.class,
                () -> store.findByPayerIdAndEnvironment("PAYER-BAD", Environment.PRODUCTION));
        assertEquals("UnrecognizedPropertyException", e.problem());
    }

    @Test
    void saveOverAnEntryMissingARequiredFieldRepairsItInPlace(@TempDir Path dir) throws Exception {
        Path file = storeWith(dir, Bad.OAUTH2_MISSING_CLIENT_ID);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-BAD").authType(AuthType.OAUTH2_CLIENT_CREDENTIALS)
                .tokenEndpoint("https://auth.example/token").clientId("client").build());

        assertEquals("client", new PayerRouter(store).resolve("PAYER-BAD", Environment.PRODUCTION).clientId());
        assertEquals(List.of("PAYER-BAD", "PAYER-OK"),
                new FileBasedConnectionStore(file).findAll().stream().map(ConnectionRecord::payerId).toList());
    }

    /** Delete is how the API clears a broken entry. */
    @ParameterizedTest
    @EnumSource(value = Bad.class, mode = EnumSource.Mode.EXCLUDE, names = "UNKNOWN_ENVIRONMENT")
    void deleteRemovesAnInvalidEntry(Bad bad, @TempDir Path dir) throws Exception {
        Path file = storeWith(dir, bad);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.delete("PAYER-BAD", Environment.PRODUCTION);

        assertEquals(List.of(), store.findByPayerId("PAYER-BAD"));
        assertEquals(1, nodes(file).size());
        assertEquals(List.of("PAYER-OK"), store.findByPayerId("PAYER-OK").stream().map(ConnectionRecord::payerId).toList());
    }

    @Test
    void savingAnExistingKeyKeepsItsPosition(@TempDir Path dir) {
        FileBasedConnectionStore store = new FileBasedConnectionStore(dir.resolve("connections.yaml"));
        for (String payerId : List.of("A", "B", "C")) {
            store.save(recordFor(payerId).build());
        }

        store.save(recordFor("A").displayName("renamed").build());

        assertEquals(List.of("A", "B", "C"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
        assertEquals("renamed", store.findAll().get(0).displayName());
    }

    @Test
    void aNullOrScalarListItemIsKeptByAWrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, "-\n- \"SENTINEL-UNKNOWN-VALUE\"\n" + OK_ENTRY);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(List.of("PAYER-OK"), store.findAll().stream().map(ConnectionRecord::payerId).toList());
        store.save(recordFor("PAYER-NEW").build());

        assertEquals(List.of(new FileBasedConnectionStore.InvalidEntry(0, null, null, "NullEntry"),
                        new FileBasedConnectionStore.InvalidEntry(1, null, null, "MismatchedInputException")),
                store.invalidEntries());

        JsonNode after = nodes(file);
        assertEquals(4, after.size());
        assertTrue(after.get(0).isNull());
        assertEquals("SENTINEL-UNKNOWN-VALUE", after.get(1).asText());
    }

    @ParameterizedTest
    @EnumSource(Bad.class)
    void invalidEntriesListsTheEntryByKeyAndProblem(Bad bad, @TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, bad));

        assertEquals(List.of(new FileBasedConnectionStore.InvalidEntry(0, "PAYER-BAD",
                        bad.keyed ? Environment.PRODUCTION : null, bad.problem)),
                store.invalidEntries());
    }

    @Test
    void invalidEntriesIsEmptyForAGoodOrMissingFile(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        assertEquals(List.of(), store.invalidEntries());

        Files.writeString(file, OK_ENTRY);
        assertEquals(List.of(), store.invalidEntries());
    }

    @Test
    void invalidEntriesFollowsADeleteThatClearsTheEntry(@TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, Bad.UNKNOWN_AUTH_TYPE));
        assertEquals(1, store.invalidEntries().size());

        store.delete("PAYER-BAD", Environment.PRODUCTION);

        assertEquals(List.of(), store.invalidEntries());
    }

    /** Only a scalar payerId and a known environment name give an invalid entry a key. */
    @Test
    void anInvalidEntryWithoutAReadableKeyMatchesNoLookup(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - environment: "PRODUCTION"
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "NONE"
                - payerId: null
                  environment: "PRODUCTION"
                  authType: "NONE"
                - payerId: 42
                  environment: 2
                  authType: "FUTURE_AUTH_SENTINEL"
                - payerId: ["PAYER-OK"]
                  environment: "PRODUCTION"
                """ + OK_ENTRY);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(List.of(
                        new FileBasedConnectionStore.InvalidEntry(0, null, Environment.PRODUCTION, "NullPointerException"),
                        new FileBasedConnectionStore.InvalidEntry(1, null, Environment.PRODUCTION, "NullPointerException"),
                        new FileBasedConnectionStore.InvalidEntry(2, "42", null, "InvalidFormatException"),
                        new FileBasedConnectionStore.InvalidEntry(3, null, Environment.PRODUCTION, "MismatchedInputException")),
                store.invalidEntries());
        assertEquals("https://ok.example/r4", new PayerRouter(store).resolve("PAYER-OK").baseUrl());
        assertThrows(InvalidConnectionRecordException.class, () -> store.findByPayerId("42"));
    }

    /** A save writes over the first entry with its key and drops later ones, as the old remove-then-add did. */
    @Test
    void saveOverADuplicatedKeyKeepsOneEntry(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, OK_ENTRY + OK_ENTRY.replace("ok.example", "second.example"));
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-OK").baseUrl("https://saved.example/r4").build());

        assertEquals(List.of("PAYER-OK:PRODUCTION https://saved.example/r4"), baseUrls(store.findAll()));
        assertEquals(1, nodes(file).size());
    }

    /** The exception for a key carries the key and problem, for a caller that wants to tell this case apart. */
    @Test
    void theKeyExceptionExposesTheKeyAndProblem(@TempDir Path dir) throws Exception {
        FileBasedConnectionStore store = new FileBasedConnectionStore(storeWith(dir, Bad.UNKNOWN_STATUS));

        InvalidConnectionRecordException e = assertThrows(InvalidConnectionRecordException.class,
                () -> store.findByPayerIdAndEnvironment("PAYER-BAD", Environment.PRODUCTION));

        assertEquals("PAYER-BAD", e.payerId());
        assertEquals(Environment.PRODUCTION, e.environment());
        assertEquals("InvalidFormatException", e.problem());
        assertNull(e.getCause());
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
