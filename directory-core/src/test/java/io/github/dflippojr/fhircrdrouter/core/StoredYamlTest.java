package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** #231: the tree a rewrite writes keeps a plain scalar's spelling and type. */
class StoredYamlTest {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory());

    private static JsonNode read(String yaml) throws Exception {
        return YAML.readValue(yaml.getBytes(StandardCharsets.UTF_8), StoredYaml.Document.class).root();
    }

    @Test
    void plainNumbersAndBooleansKeepTheirTextAndKind() throws Exception {
        JsonNode root = read("""
                int: 010
                float: 1.10
                flag: yes
                text: "1.10"
                none: ~
                list: [1.0, off]
                """);

        assertEquals(new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "010"), root.get("int"));
        assertEquals(JsonNodeType.NUMBER, root.get("float").getNodeType());
        assertEquals(JsonToken.VALUE_NUMBER_FLOAT, root.get("float").asToken());
        assertEquals("1.10", root.get("float").asText());
        assertEquals(JsonNodeType.BOOLEAN, root.get("flag").getNodeType());
        assertEquals("yes", root.get("flag").asText());
        assertEquals(new TextNode("1.10"), root.get("text"));
        assertTrue(root.get("none").isNull());
        assertEquals("off", root.get("list").get(1).asText());
    }

    @Test
    void theRewriteWritesPlainScalarsBackUnquoted() throws Exception {
        JsonNode root = read("a: 1.10\nb: [yes, 2]\nc: null\nnan: .nan\ninf: -.inf\n");

        assertEquals("---\na: 1.10\nb:\n- yes\n- 2\nc: null\nnan: .nan\ninf: -.inf\n", YAML.writeValueAsString(root));
    }

    /** The generator quotes a leading zero: the spelling survives, the YAML type not. */
    @Test
    void aLeadingZeroNumberKeepsItsSpelling() throws Exception {
        assertEquals("---\no: '007'\n", YAML.writeValueAsString(read("o: 007\n")));
    }

    private static List<String> problemPaths(String yaml) throws Exception {
        return StoredYaml.problems(read(yaml)).stream().map(p -> p.path() + ": " + p.reason()).toList();
    }

    /** Each value the writer cannot write back as read is found by path; YAML's own tags and plain values are not. */
    @Test
    void problemsAreFoundByPath() throws Exception {
        assertEquals(List.of("f: an explicit YAML tag that disagrees with its plain text"), problemPaths("f: !!float 1\n"));
        assertEquals(List.of("a.b[1]: an explicit YAML tag that disagrees with its plain text"),
                problemPaths("a: {b: [1, !!float 2]}\n"));
        assertEquals(List.of("z: a number with a leading zero"), problemPaths("z: 010\n"));
        assertEquals(List.of("s: a duplicate key"), problemPaths("s: 1\ns: 2\n"));
        assertEquals(List.of("m: a YAML type id the rewrite cannot keep", "q[0]: a YAML type id the rewrite cannot keep"),
                problemPaths("m: !<limit> {count: 2}\nq: [!<code> abc]\n"));
        assertEquals(List.of(), problemPaths(
                "i: !!int 7\nf: !!float 1.5\nb: !!bool yes\ns: !!str 3\nm: !!map {a: 1}\nq: !!seq [x]\nplain: 1\n"));
    }

    /** A value the store refuses to write fails if it is ever written, instead of being written changed. */
    @Test
    void anUnwritableValueRefusesToBeWritten() throws Exception {
        JsonNode root = read("s: 1\ns: 2\n");

        assertTrue(root.get("s") instanceof StoredYaml.Unwritable);
        assertEquals("2", root.get("s").asText());
        assertEquals(root.get("s"), read("s: 0\ns: 2\n").get("s"));
        assertEquals(root.get("s").hashCode(), read("s: 0\ns: 2\n").get("s").hashCode());
        assertEquals(JsonToken.VALUE_EMBEDDED_OBJECT, root.get("s").asToken());
        assertEquals(JsonNodeType.POJO, root.get("s").getNodeType());
        assertThrows(Exception.class, () -> YAML.writeValueAsString(root));
        assertNotEquals(root.get("s"), read("s: 0\ns: 3\n").get("s"));
        assertNotEquals(root.get("s"), read("s: !<x> 2\n").get("s"));
        assertNotEquals(root.get("s"), new TextNode("2"));
    }

    @Test
    void plainScalarEqualityIsByKindAndText() {
        StoredYaml.PlainScalar one = new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1");

        assertEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1"));
        assertEquals(one.hashCode(), new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1").hashCode());
        assertNotEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_FLOAT, "1"));
        assertNotEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "01"));
        assertFalse(one.equals(new TextNode("1")));
    }
}
