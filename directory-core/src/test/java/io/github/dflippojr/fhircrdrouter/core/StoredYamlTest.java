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

/** #231: the store's YAML tree keeps a plain scalar's spelling, for binding and for the rewrite. */
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

        assertEquals(new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "010", 10), root.get("int"));
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
    void bindingSeesTheTextAndTheRewriteWritesItBackUnquoted() throws Exception {
        JsonNode root = read("a: 1.10\nb: [yes, 2]\nc: null\n");

        JsonNode binding = StoredYaml.forBinding(root);
        assertTrue(binding.get("a").isBigDecimal());
        assertEquals("1.10", binding.get("a").numberValue().toString());
        assertEquals(new TextNode("yes"), binding.get("b").get(0));
        assertEquals(2, binding.get("b").get(1).intValue());
        assertEquals("2", binding.get("b").get(1).numberValue().toString());
        assertTrue(binding.get("c").isNull());
        assertEquals("---\na: 1.10\nb:\n- yes\n- 2\nc: null\n", YAML.writeValueAsString(root));
    }

    @Test
    void aFloatBindsAsItsExactDecimalOrAsItsSpellingWhereItHasNoNumber() throws Exception {
        JsonNode root = read("d: 0.1000000000000000055511151231257827\nnan: .nan\ninf: -.inf\n");
        JsonNode binding = StoredYaml.forBinding(root);

        assertEquals(new java.math.BigDecimal("0.1000000000000000055511151231257827"), binding.get("d").decimalValue());
        assertEquals(new TextNode(".nan"), binding.get("nan"));
        assertEquals(new TextNode("-.inf"), binding.get("inf"));
        assertEquals("---\nd: 0.1000000000000000055511151231257827\nnan: .nan\ninf: -.inf\n", YAML.writeValueAsString(root));
    }

    @Test
    void aSpelledNumberIsItsValueWithItsSpelling() {
        Number n = new StoredYaml.SpelledNumber("+2.50", 2.5);

        assertEquals("+2.50", n.toString());
        assertEquals(2, n.intValue());
        assertEquals(2L, n.longValue());
        assertEquals(2.5f, n.floatValue());
        assertEquals(2.5, n.doubleValue());
    }

    @Test
    void aTaggedScalarIsWrittenSoItReadsBackAsTheSameType() throws Exception {
        JsonNode root = read("f: !!float 1\ng: !!float 1.5\nb: !!bool true\n");

        assertEquals("---\nf: 1.0\ng: 1.5\nb: true\n", YAML.writeValueAsString(root));
        // What it binds as is still its spelling.
        assertEquals("1", root.get("f").asText());
        assertEquals("1", StoredYaml.forBinding(root).get("f").numberValue().toString());
    }

    @Test
    void plainScalarEqualityIsByKindAndText() {
        StoredYaml.PlainScalar one = new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1", 1);

        assertEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1", 1));
        assertEquals(one.hashCode(), new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1", 1).hashCode());
        assertNotEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_FLOAT, "1", 1.0));
        assertNotEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "01", 1));
        assertNotEquals(one, new StoredYaml.PlainScalar(JsonToken.VALUE_NUMBER_INT, "1", "1.0", 1));
        assertFalse(one.equals(new TextNode("1")));
    }
}
