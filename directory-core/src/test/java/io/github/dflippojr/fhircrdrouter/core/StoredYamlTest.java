package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** #231: the tree a rewrite writes keeps a plain scalar's spelling and type, and marks what is not plain. */
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

    /** The file's first entry as the store reads it for a rewrite: each value outside the plain tree wrapped. */
    private static JsonNode entry(String yaml) throws Exception {
        byte[] bytes = yaml.getBytes(StandardCharsets.UTF_8);
        ArrayNode root = (ArrayNode) YAML.readValue(bytes, StoredYaml.Document.class).root();
        assertNull(StoredYaml.allowlist(root, bytes));
        return root.get(0);
    }

    private static List<String> problemPaths(String yaml) throws Exception {
        return StoredYaml.problems(entry(yaml)).stream().map(p -> p.path() + ": " + p.reason()).toList();
    }

    /**
     * Each value outside the plain tree (an anchor, an alias, any explicit tag, a duplicate key) is found by path,
     * as is a number the writer cannot write back; a plain value, in any scalar style, is not (#231, allowlist).
     */
    @Test
    void problemsAreFoundByPath() throws Exception {
        assertEquals(List.of("f: a YAML tag"), problemPaths("- f: !!float 1\n"));
        assertEquals(List.of("a.b[1]: a YAML tag"), problemPaths("- a: {b: [1, !!float 2]}\n"));
        assertEquals(List.of("z: a number with a leading zero"), problemPaths("- z: 010\n"));
        assertEquals(List.of("s: a duplicate key"), problemPaths("- s: 1\n  s: 2\n"));
        assertEquals(List.of("m: a YAML tag", "q[0]: a YAML tag"),
                problemPaths("- m: !<limit> {count: 2}\n  q: [!<code> abc]\n"));
        assertEquals(List.of("i: a YAML tag", "f: a YAML tag", "b: a YAML tag", "s: a YAML tag", "m: a YAML tag",
                        "q: a YAML tag", "n: a YAML tag"),
                problemPaths("- i: !!int 7\n  f: !!float 1.5\n  b: !!bool yes\n  s: !!str 3\n  m: !!map {a: 1}\n"
                        + "  q: !!seq [x]\n  n: ! 1\n  plain: 1\n"));
        assertEquals(List.of("a: a YAML anchor", "b: a YAML alias", "c[0]: a YAML anchor"),
                problemPaths("- a: &x 1\n  b: *x\n  c: [&y {d: 1}]\n"));
        assertEquals(List.of("j: a YAML anchor on its key", "k: a YAML tag on its key"),
                problemPaths("- &k j: 1\n  !!str k: 2\n"));
        assertEquals(List.of(": a YAML anchor"), problemPaths("- &e {a: &x 1}\n"));
        assertEquals(List.of(), problemPaths("- i: 1\n  s: \"x\"\n  t: 'y'\n  b: |\n    text\n  q: [x, {y: 2}]\n"));
    }

    /**
     * A duplicate key's tree keeps its last value, so a value outside the plain tree in an earlier one has no node
     * of its own: the key's value is wrapped instead, whatever the last value's shape.
     */
    @Test
    void aValueInAnEarlierDuplicateWrapsTheKey() throws Exception {
        assertEquals(List.of("s: a YAML anchor"), problemPaths("- s: {a: &x 1}\n  s: 2\n"));
        assertEquals(List.of("s: a YAML anchor"), problemPaths("- s: {a: &x 1}\n  s: {b: 2}\n"));
    }

    /** What is outside the plain tree for the document as a whole: the list's own tag or anchor, a second document. */
    @Test
    void theDocumentItselfCanBeUnwritable() throws Exception {
        for (String[] c : new String[][] {
                {"--- !!seq\n- a: 1\n", "a YAML tag"},
                {"--- &l\n- a: 1\n", "a YAML anchor"},
                {"- a: 1\n---\n- b: 2\n", "a second YAML document"}}) {
            byte[] bytes = c[0].getBytes(StandardCharsets.UTF_8);
            ArrayNode root = (ArrayNode) YAML.readValue(bytes, StoredYaml.Document.class).root();
            assertEquals(c[1], StoredYaml.allowlist(root, bytes), c[0]);
        }
    }

    /** Events that do not match the tree the store read refuse the whole document rather than write it. */
    @Test
    void eventsThatDoNotMatchTheTreeRefuseTheDocument() {
        String refused = "YAML the rewrite could not check";

        assertEquals(refused, StoredYaml.allowlist(YAML.createArrayNode(), "- &x 1\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(refused, StoredYaml.allowlist(YAML.createArrayNode(), "a: 1\n".getBytes(StandardCharsets.UTF_8)));
        assertEquals(refused, StoredYaml.allowlist(YAML.createArrayNode(), "- [\n".getBytes(StandardCharsets.UTF_8)));
    }

    /** A value the store refuses to write fails if it is ever written, instead of being written changed. */
    @Test
    void anUnwritableValueRefusesToBeWritten() throws Exception {
        JsonNode root = entry("- s: 1\n  s: 2\n");

        assertTrue(root.get("s") instanceof StoredYaml.Unwritable);
        assertEquals("2", root.get("s").asText());
        assertEquals(root.get("s"), entry("- s: 0\n  s: 2\n").get("s"));
        assertEquals(root.get("s").hashCode(), entry("- s: 0\n  s: 2\n").get("s").hashCode());
        assertEquals(JsonToken.VALUE_EMBEDDED_OBJECT, root.get("s").asToken());
        assertEquals(JsonNodeType.POJO, root.get("s").getNodeType());
        assertThrows(Exception.class, () -> YAML.writeValueAsString(root));
        assertNotEquals(root.get("s"), entry("- s: 0\n  s: 3\n").get("s"));
        assertNotEquals(root.get("s"), entry("- s: !<x> 2\n").get("s"));
        assertNotEquals(root.get("s"), entry("- s: &a 2\n").get("s")); // the same value, another reason
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
