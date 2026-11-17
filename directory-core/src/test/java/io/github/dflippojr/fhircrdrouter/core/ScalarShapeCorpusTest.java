package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * #231: a sweep over the scalar shapes YAML allows, in a string, a time and an enum field. Two checks per shape:
 * <ol>
 *   <li>a readable entry binds exactly as the whole-file typed binding before #231 bound it (the oracle), or,
 *   where that failed, is an invalid entry;</li>
 *   <li>after a save of another payer, the untouched entries, the readable one and one that holds the shape in a
 *   property this version does not know, parse to the same nodes and bind to the same records.</li>
 * </ol>
 */
class ScalarShapeCorpusTest {

    /** The store's mapper before #231, which bound the whole file as {@code ConnectionRecord[]}. */
    private static final ObjectMapper ORACLE = new ObjectMapper(new YAMLFactory())
            .registerModule(new JavaTimeModule())
            .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
            .enable(SerializationFeature.INDENT_OUTPUT);

    private static final ObjectMapper PLAIN = new ObjectMapper(new YAMLFactory());

    private static final List<String> SCALARS = List.of(
            "1.10", "+2", "-0", "007", "010", "0x1F", "0o17", "1e3", "1.5e3", ".5", ".nan", "-.inf", "99999999999999999999",
            "~", "null", "yes", "no", "on", "off", "y", "n", "true", "False",
            "!!float 1", "!!int 7", "!!str 3", "!!bool yes", "!!null ''", "!!binary AQI=", "! 3",
            "2026-01-01", "2026-01-01T10:00:00Z", "2026-01-01 10:00:00",
            "'single'", "\"double\"", "plain text", "\"\"", "''",
            "|\n    line one\n    line two", ">\n    folded\n    text", "|-\n    kept",
            "&anchor 1.10", "[a, 1.10]", "{k: 1.10}");

    private static final List<String> TIMES = List.of(
            "5", "+5", "-1.5", "1730000000.123456789", "0x10", "!!float 1", "!!str 5",
            "2026-01-01T10:00:00Z", "\"2026-01-01T10:00:00.123456789Z\"", "2026-01-01", "~", "010", "02", "08");

    private static final List<String> ENVIRONMENTS = List.of(
            "PRODUCTION", "2", "+2", "0x2", "!!int 2", "!!str 2", "!!float 2", "\"2\"", "production", "~", "7",
            "02", "002", "010");

    /**
     * Numbers with a leading zero, which YAML reads as octal ({@code 010} is 8) and the generator writes back
     * quoted, as a string. In a known field of a readable entry the rewrite writes the field's bound value
     * instead, so it binds as before; anywhere else its type is unknown and the write refuses (#231).
     */
    private static final List<String> LEADING_ZERO = List.of("007", "010", "02", "002");

    /**
     * Shapes outside the plain tree a rewrite may write back: an explicit tag, YAML's own included, or an anchor.
     * The generator writes neither, so a rewrite could change how the entry binds ({@code environment: !!float 2}
     * would become the readable {@code 2}); writes refuse instead and leave the file as it was (#231, owner
     * decisions: option 3, then the allowlist).
     */
    private static final List<String> NOT_PLAIN = List.of(
            "!!float 1", "!!int 7", "!!str 3", "!!bool yes", "!!null ''", "!!binary AQI=", "&anchor 1.10",
            "!!str 5", "!!int 2", "!!str 2", "!!float 2", "! 3");

    static Stream<Arguments> shapes() {
        return Stream.of(
                SCALARS.stream().map(s -> Arguments.of("igVersion", s)),
                TIMES.stream().map(s -> Arguments.of("lastVerifiedAt", s)),
                ENVIRONMENTS.stream().map(s -> Arguments.of("environment", s))).flatMap(s -> s);
    }

    /**
     * The file as the store's tree: each plain scalar compared by its spelling and kind, which is stricter
     * than Jackson's own tree (that reads 1.10 and 1.1 alike) and also reads {@code .nan}.
     */
    private static JsonNode nodes(Path file) throws Exception {
        return PLAIN.readValue(Files.readAllBytes(file), StoredYaml.Document.class).root();
    }

    private static String entry(String payerId, String field, String shape) {
        StringBuilder yaml = new StringBuilder("- payerId: \"").append(payerId).append("\"\n");
        if (!field.equals("environment")) {
            yaml.append("  environment: \"PRODUCTION\"\n");
        }
        yaml.append("  baseUrl: \"https://").append(payerId.toLowerCase()).append(".example/r4\"\n")
                .append("  authType: \"NONE\"\n")
                .append("  createdAt: \"2026-01-01T00:00:00Z\"\n")
                .append("  updatedAt: \"2026-01-01T00:00:00Z\"\n")
                .append("  ").append(field).append(": ").append(shape).append('\n');
        return yaml.toString();
    }

    @ParameterizedTest(name = "{0}: {1}")
    @MethodSource("shapes")
    void aShapeBindsAsBeforeAndSurvivesARewrite(String field, String shape, @TempDir Path dir) throws Exception {
        String readable = entry("PAYER-A", field, shape);
        String unknown = entry("PAYER-U", "futureField", shape);
        ConnectionRecord expected;
        try {
            expected = ORACLE.readValue(readable, ConnectionRecord[].class)[0];
        } catch (Exception e) {
            expected = null;
        }
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, readable + unknown);
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        // 1. The readable entry binds as the oracle bound it, or is invalid where the oracle failed.
        assertEquals(expected == null ? List.of() : List.of(expected), store.findAll());
        assertEquals(expected == null ? 2 : 1, store.invalidEntries().size());

        // 2. A save of another payer leaves both entries as they were, or refuses where it cannot.
        if (LEADING_ZERO.contains(shape)) {
            // The unknown field's type is unknown, so a rewrite refuses; with the readable entry alone, it goes
            // ahead and the entry binds as before (or refuses, where the entry is not readable).
            assertRefuses(store, file);
            Files.writeString(file, readable);
            FileBasedConnectionStore alone = new FileBasedConnectionStore(file);
            if (expected == null) {
                assertRefuses(alone, file);
                return;
            }
            alone.save(other());
            alone.delete("PAYER-NEW", Environment.SANDBOX);
            assertEquals(List.of(expected), new FileBasedConnectionStore(file).findAll());
            return;
        }
        if (NOT_PLAIN.contains(shape)) {
            assertRefuses(store, file);
            return;
        }
        JsonNode before = nodes(file);
        List<FileBasedConnectionStore.InvalidEntry> invalidBefore = store.invalidEntries();
        store.save(ConnectionRecord.builder().payerId("PAYER-NEW").environment(Environment.SANDBOX)
                .baseUrl("https://new.example/r4").authType(AuthType.NONE).build());

        JsonNode after = nodes(file);
        assertEquals(before.get(0), after.get(0));
        assertEquals(before.get(1), after.get(1));
        FileBasedConnectionStore reread = new FileBasedConnectionStore(file);
        assertEquals(expected == null ? List.of() : List.of(expected),
                reread.findAll().stream().filter(r -> r.payerId().equals("PAYER-A")).toList());
        assertEquals(invalidBefore, reread.invalidEntries());
    }

    private static ConnectionRecord other() {
        return ConnectionRecord.builder().payerId("PAYER-NEW").environment(Environment.SANDBOX)
                .baseUrl("https://new.example/r4").authType(AuthType.NONE).build();
    }

    private static void assertRefuses(FileBasedConnectionStore store, Path file) throws Exception {
        byte[] bytes = Files.readAllBytes(file);
        assertThrows(RouterException.class, () -> store.save(other()));
        assertArrayEquals(bytes, Files.readAllBytes(file));
    }

    /**
     * An anchor and its alias read as the oracle read them. Neither is in the plain tree a rewrite may write back,
     * so a save of another payer refuses and leaves the bytes unchanged (#231, owner decision: allowlist).
     */
    @Test
    void anAnchorAndAnAliasBindAsBeforeAndRefuseARewrite(@TempDir Path dir) throws Exception {
        String yaml = """
                - payerId: "PAYER-A"
                  environment: "PRODUCTION"
                  baseUrl: &url "https://a.example/r4"
                  authType: "NONE"
                  createdAt: "2026-01-01T00:00:00Z"
                  updatedAt: "2026-01-01T00:00:00Z"
                - payerId: "PAYER-B"
                  environment: "PRODUCTION"
                  baseUrl: *url
                  authType: "NONE"
                  createdAt: "2026-01-01T00:00:00Z"
                  updatedAt: "2026-01-01T00:00:00Z"
                """;
        Path file = dir.resolve("connections.yaml");
        Files.writeString(file, yaml);
        List<ConnectionRecord> expected = List.of(ORACLE.readValue(yaml, ConnectionRecord[].class));
        FileBasedConnectionStore store = new FileBasedConnectionStore(file);

        assertEquals(expected, store.findAll());
        assertRefuses(store, file);
        assertEquals(expected, new FileBasedConnectionStore(file).findAll());
    }
}
