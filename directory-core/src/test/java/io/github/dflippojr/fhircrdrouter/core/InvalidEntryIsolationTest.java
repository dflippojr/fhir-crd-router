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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
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
                        new FileBasedConnectionStore.InvalidEntry(2, "42", Environment.PRODUCTION, "InvalidFormatException"),
                        new FileBasedConnectionStore.InvalidEntry(3, null, Environment.PRODUCTION, "MismatchedInputException")),
                store.invalidEntries());
        assertEquals("https://ok.example/r4", new PayerRouter(store).resolve("PAYER-OK").baseUrl());
        assertThrows(InvalidConnectionRecordException.class, () -> store.findByPayerId("42"));
    }

    /** A null payerId matched nothing before #231; with an unkeyed invalid entry present it still does. */
    @Test
    void aNullPayerIdMatchesNothing(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - environment: "PRODUCTION"
                  authType: "NONE"
                """ + OK_ENTRY);
        byte[] before = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(List.of(), store.findByPayerId(null));
        assertTrue(store.findByPayerIdAndEnvironment(null, Environment.PRODUCTION).isEmpty());
        store.delete(null, Environment.PRODUCTION);

        assertArrayEquals(before, Files.readAllBytes(file));
        assertEquals(2, store.invalidEntries().size() + store.findAll().size());
    }

    /**
     * The key is read with the binding's own rules: Jackson binds an enum ordinal ({@code environment: 2})
     * to {@code PRODUCTION}, so an entry written that way keeps its key when another field fails.
     */
    @Test
    void anInvalidEntryWithANumericEnvironmentKeepsItsKey(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-BAD"
                  environment: 2
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "OAUTH2_CLIENT_CREDENTIALS"
                  tokenEndpoint: "https://sentinel-token.example/token"
                """ + OK_ENTRY);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertThrows(InvalidConnectionRecordException.class,
                () -> new PayerRouter(store).resolve("PAYER-BAD", Environment.PRODUCTION));
        store.delete("PAYER-BAD", Environment.PRODUCTION);
        assertEquals(List.of(), store.invalidEntries());
        assertEquals(1, nodes(file).size());
    }

    /** A null environment matched nothing before #231, and must not match an entry whose environment is unknown. */
    @Test
    void aNullEnvironmentMatchesNothing(@TempDir Path dir) throws Exception {
        Path file = storeWith(dir, Bad.UNKNOWN_ENVIRONMENT);
        byte[] before = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertTrue(store.findByPayerIdAndEnvironment("PAYER-BAD", null).isEmpty());
        store.delete("PAYER-BAD", null);

        assertArrayEquals(before, Files.readAllBytes(file));
    }

    /**
     * An unquoted YAML scalar keeps its spelling, as the typed binding before #231 kept it: {@code 1.10} is the
     * payerId "1.10", not 1.1. A rewrite writes a plain number or boolean back as it was spelled, in an
     * untouched entry, an unknown field and a known one alike.
     */
    @Test
    void unquotedScalarsKeepTheirSpelling(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: 1.10
                  environment: "PRODUCTION"
                  baseUrl: "https://ok.example/r4"
                  authType: "NONE"
                  igVersion: 2.10
                - payerId: 7.50
                  environment: 2
                  baseUrl: "https://bad.example/r4"
                  authType: "NONE"
                  futureRatio: 1.50
                  futureFlag: yes
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals("2.10", store.findByPayerIdAndEnvironment("1.10", Environment.PRODUCTION).orElseThrow().igVersion());
        assertEquals(List.of(new FileBasedConnectionStore.InvalidEntry(1, "7.50", Environment.PRODUCTION,
                "UnrecognizedPropertyException")), store.invalidEntries());

        store.save(recordFor("PAYER-NEW").build());

        String written = Files.readString(file);
        for (String kept : List.of("payerId: 1.10", "igVersion: 2.10", "payerId: 7.50", "environment: 2",
                "futureRatio: 1.50", "futureFlag: yes")) {
            assertTrue(written.contains(kept), kept + " not in\n" + written);
        }
        FileBasedConnectionStore reread = new FileBasedConnectionStore(file);
        assertEquals("2.10", reread.findByPayerIdAndEnvironment("1.10", Environment.PRODUCTION).orElseThrow().igVersion());
        assertEquals("7.50", reread.invalidEntries().get(0).payerId());
    }

    /** A {@code !!binary} value in an untouched entry is still binary after a rewrite (compares parsed nodes). */
    @Test
    void aBinaryValueSurvivesARewrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-BAD"
                  environment: "PRODUCTION"
                  baseUrl: "https://bad.example/r4"
                  authType: "NONE"
                  futureBytes: !!binary AQI=
                """ + OK_ENTRY);
        JsonNode before = nodes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-NEW").build());

        JsonNode after = nodes(file);
        assertTrue(before.get(0).get("futureBytes").isBinary());
        assertEquals(before.get(0), after.get(0));
    }

    /**
     * A plain number binds as the typed binding bound it: as a number for an enum or time field
     * ({@code environment: +2} is {@code PRODUCTION}) and as its spelling for a string field.
     */
    @Test
    void aSignedNumberBindsAsANumberAndAsText(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: +2
                  environment: +2
                  baseUrl: "https://ok.example/r4"
                  authType: "NONE"
                  lastVerifiedAt: 5
                  igVersion: 99999999999999999999
                - payerId: "PAYER-BAD"
                  environment: +2
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "OAUTH2_CLIENT_CREDENTIALS"
                  tokenEndpoint: "https://sentinel-token.example/token"
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        ConnectionRecord ok = store.findByPayerIdAndEnvironment("+2", Environment.PRODUCTION).orElseThrow();
        assertEquals(java.time.Instant.ofEpochSecond(5), ok.lastVerifiedAt());
        assertEquals("99999999999999999999", ok.igVersion());
        InvalidConnectionRecordException e = assertThrows(InvalidConnectionRecordException.class,
                () -> store.findByPayerIdAndEnvironment("PAYER-BAD", Environment.PRODUCTION));
        assertEquals("IllegalArgumentException", e.problem());
    }

    /**
     * The canonical form a tagged number is written in is not what it binds as: {@code !!float 1} binds as
     * "1", as the typed binding gave it. A decimal time keeps every digit ({@code .123456789} seconds).
     */
    @Test
    void aTaggedNumberBindsAsItsSpellingAndADecimalTimeKeepsItsPrecision(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: !!float 1
                  environment: "PRODUCTION"
                  baseUrl: "https://ok.example/r4"
                  authType: "NONE"
                  lastVerifiedAt: 1730000000.123456789
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        ConnectionRecord record = store.findByPayerIdAndEnvironment("1", Environment.PRODUCTION).orElseThrow();
        assertEquals(java.time.Instant.ofEpochSecond(1730000000L, 123456789L), record.lastVerifiedAt());
    }

    /**
     * The YAML generator writes no scalar tag, so a rewrite would turn {@code environment: !!float 2} (no enum
     * index, so invalid) into {@code environment: 2}, which binds as {@code PRODUCTION}. A write that would
     * drop a tag disagreeing with its plain text refuses, names the entry and leaves the bytes unchanged
     * (#231, owner decision: option 3).
     */
    @Test
    void aWriteThatWouldDropADisagreeingTagRefusesAndLeavesTheBytesUnchanged(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-BAD"
                  environment: !!float 2
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "NONE"
                """ + OK_ENTRY);
        byte[] before = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        RouterException onSave = assertThrows(RouterException.class, () -> store.save(recordFor("PAYER-NEW").build()));
        RouterException onDelete = assertThrows(RouterException.class,
                () -> store.delete("PAYER-OK", Environment.PRODUCTION));

        for (RouterException e : List.of(onSave, onDelete)) {
            assertTrue(e.getMessage().contains("entry 0"), e.getMessage());
            assertTrue(e.getMessage().contains("payerId=PAYER-BAD"), e.getMessage());
            assertTrue(e.getMessage().contains("field environment"), e.getMessage());
            assertNoSentinel(e);
        }
        assertArrayEquals(before, Files.readAllBytes(file));
        assertEquals("https://ok.example/r4", new PayerRouter(store).resolve("PAYER-OK").baseUrl());
    }

    /** A tag on a field the save sets is overwritten by the save, so it does not block the write. */
    @Test
    void aSaveThatSetsTheTaggedFieldIsAllowed(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: "https://a.example/r4"
                  authType: "NONE"
                  igVersion: !!float 1
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-A").igVersion("crd-2.2.1").build());

        assertEquals("crd-2.2.1", new FileBasedConnectionStore(file).findAll().get(0).igVersion());
    }

    /** A disagreeing tag in a field this version does not know, on the saved entry itself, still refuses. */
    @Test
    void aSaveOverAnEntryWithATaggedUnknownFieldRefuses(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: "https://a.example/r4"
                  authType: "NONE"
                  futureLimits: [1, !!float 2]
                """);
        byte[] before = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        RouterException e = assertThrows(RouterException.class,
                () -> store.save(recordFor("PAYER-A").displayName("renamed").build()));

        assertTrue(e.getMessage().contains("field futureLimits[1]"), e.getMessage());
        assertArrayEquals(before, Files.readAllBytes(file));
    }

    /**
     * YAML reads a leading-zero number as octal ({@code 02} is 2, {@code 010} is 8), and the generator writes it
     * back quoted, as a string, which would bind differently ({@code "02"} is no environment, {@code "010"} is
     * epoch second 10). In a known field of a readable entry the rewrite writes the bound value instead, so the
     * entry binds as before, through a save and a delete of other payers (#231).
     */
    @Test
    void aLeadingZeroNumberInAReadableEntryStillBindsAfterARewrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: 007
                  environment: 02
                  baseUrl: "https://ok.example/r4"
                  authType: "NONE"
                  lastVerifiedAt: 010
                  createdAt: "2026-01-01T00:00:00Z"
                  updatedAt: "2026-01-01T00:00:00Z"
                """);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        ConnectionRecord before = store.findAll().get(0);
        assertEquals(Environment.PRODUCTION, before.environment());
        assertEquals(java.time.Instant.ofEpochSecond(8), before.lastVerifiedAt());

        store.save(recordFor("PAYER-NEW").build());
        store.delete("PAYER-NEW", Environment.PRODUCTION);

        assertEquals(List.of(before), new FileBasedConnectionStore(file).findAll());
    }

    /** Where the type is unknown (an unreadable entry, or a field this version does not know), the write refuses. */
    @Test
    void aLeadingZeroNumberWhoseTypeIsUnknownRefusesTheWrite(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, """
                - payerId: "PAYER-BAD"
                  environment: 02
                  baseUrl: "https://sentinel-base.example/r4"
                  authType: "OAUTH2_CLIENT_CREDENTIALS"
                  tokenEndpoint: "https://sentinel-token.example/token"
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: "https://a.example/r4"
                  authType: "NONE"
                  futureCount: 010
                """ + OK_ENTRY);
        byte[] bytes = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        RouterException onSave = assertThrows(RouterException.class, () -> store.save(recordFor("PAYER-NEW").build()));
        RouterException onDelete = assertThrows(RouterException.class,
                () -> store.delete("PAYER-OK", Environment.PRODUCTION));

        for (RouterException e : List.of(onSave, onDelete)) {
            assertTrue(e.getMessage().contains("entry 0 (payerId=PAYER-BAD environment=PRODUCTION), field environment"),
                    e.getMessage());
            assertTrue(e.getMessage().contains("entry 1 (payerId=PAYER-A environment=PRODUCTION), field futureCount"),
                    e.getMessage());
            assertNoSentinel(e);
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
    }

    static final String DUPLICATE_STATUS = """
            - payerId: "PAYER-DUP"
              environment: "PRODUCTION"
              baseUrl: "https://dup.example/r4"
              authType: "NONE"
              status: "INACTIVE"
              status: "ACTIVE"
            """;

    /**
     * A rewrite cannot keep a duplicate mapping key: the tree keeps one value, so an unrelated save would turn
     * this unreadable entry (status INACTIVE, then a duplicate status ACTIVE) into a routable ACTIVE one. Writes
     * refuse while an entry they would write holds one, name it and leave the bytes unchanged (#231).
     */
    @Test
    void aDuplicateKeyRefusesTheWriteAndTheEntryStaysUnroutable(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, DUPLICATE_STATUS + OK_ENTRY);
        byte[] bytes = Files.readAllBytes(file);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);
        assertThrows(RouterException.class, () -> new PayerRouter(store).resolve("PAYER-DUP", Environment.PRODUCTION));

        RouterException onSave = assertThrows(RouterException.class, () -> store.save(recordFor("PAYER-NEW").build()));
        RouterException onDelete = assertThrows(RouterException.class,
                () -> store.delete("PAYER-OK", Environment.PRODUCTION));

        for (RouterException e : List.of(onSave, onDelete)) {
            assertTrue(e.getMessage().contains("entry 0 (payerId=PAYER-DUP environment=PRODUCTION), field status"),
                    e.getMessage());
        }
        assertArrayEquals(bytes, Files.readAllBytes(file));
        FileBasedConnectionStore reread = new FileBasedConnectionStore(file);
        assertThrows(RouterException.class, () -> new PayerRouter(reread).resolve("PAYER-DUP", Environment.PRODUCTION));
        assertEquals(1, reread.invalidEntries().size());
    }

    /** The entry's own explicit repair, or its delete, is still allowed: the save writes over the duplicate field. */
    @Test
    void anEntryWithADuplicateKeyCanStillBeRepairedOrDeleted(@TempDir Path dir) throws Exception {
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, DUPLICATE_STATUS + OK_ENTRY);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        store.save(recordFor("PAYER-DUP").status(ConnectionStatus.INACTIVE).build());

        assertEquals(ConnectionStatus.INACTIVE, new FileBasedConnectionStore(file)
                .findByPayerIdAndEnvironment("PAYER-DUP", Environment.PRODUCTION).orElseThrow().status());
        Files.writeString(file, DUPLICATE_STATUS + OK_ENTRY);
        store.delete("PAYER-DUP", Environment.PRODUCTION);
        assertEquals(List.of("PAYER-OK"), new FileBasedConnectionStore(file).findAll().stream()
                .map(ConnectionRecord::payerId).toList());
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
