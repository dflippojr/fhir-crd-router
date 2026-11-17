package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.TextNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
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

    /** Only a tag the plain text disagrees with is one a rewrite would drop; the path names where it is. */
    @Test
    void aDisagreeingTagIsFoundByPath() throws Exception {
        assertEquals("f", StoredYaml.droppedTagPath(read("f: !!float 1\n"), ""));
        assertEquals("a.b[1]", StoredYaml.droppedTagPath(read("a: {b: [1, !!float 2]}\n"), ""));
        assertEquals(null, StoredYaml.droppedTagPath(
                read("i: !!int 7\nf: !!float 1.5\nb: !!bool yes\ns: !!str 3\nplain: 1\nlist: [x]\n"), ""));
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
