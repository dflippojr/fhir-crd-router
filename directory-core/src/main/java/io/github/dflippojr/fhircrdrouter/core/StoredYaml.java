package io.github.dflippojr.fhircrdrouter.core;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BigIntegerNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ValueNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Map;
import java.util.Objects;

/**
 * The connection file as a tree that keeps each unquoted scalar as it was spelled (#231).
 *
 * <p>Jackson's own tree turns a YAML plain scalar into a number or boolean node, which loses its text:
 * {@code payerId: 1.10} becomes 1.1 and {@code 007} becomes 7. The typed binding the store used before
 * read such a value as the text {@code "1.10"}, and a rewrite of the tree would write the changed value
 * back. Here a plain number or boolean is a {@link PlainScalar} holding its text, written back unquoted
 * as it was read, and bound as that text.
 */
final class StoredYaml {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    private StoredYaml() {
    }

    /** The parsed document; read it with {@code mapper.readValue(bytes, StoredYaml.Document.class)}. */
    @JsonDeserialize(using = DocumentDeserializer.class)
    record Document(JsonNode root) { }

    static final class DocumentDeserializer extends JsonDeserializer<Document> {
        @Override
        public Document deserialize(JsonParser p, DeserializationContext ctxt) throws IOException {
            return new Document(read(p));
        }
    }

    /** Reads the value at the parser's current token. */
    static JsonNode read(JsonParser p) throws IOException {
        JsonToken token = p.currentToken();
        switch (token) {
            case START_OBJECT -> {
                ObjectNode object = NODES.objectNode();
                while (p.nextToken() == JsonToken.FIELD_NAME) {
                    String name = p.currentName();
                    p.nextToken();
                    object.set(name, read(p));
                }
                return object;
            }
            case START_ARRAY -> {
                ArrayNode array = NODES.arrayNode();
                while (p.nextToken() != JsonToken.END_ARRAY) {
                    array.add(read(p));
                }
                return array;
            }
            case VALUE_NULL -> {
                return NODES.nullNode();
            }
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> {
                return new PlainScalar(token, p.getText(), writtenText(p), numberOf(p));
            }
            case VALUE_TRUE, VALUE_FALSE -> {
                return new PlainScalar(token, p.getText(), writtenText(p), null);
            }
            case VALUE_EMBEDDED_OBJECT -> {
                // The YAML parser's only embedded value is !!binary; a binary node is written back with its tag.
                return NODES.binaryNode(p.getBinaryValue());
            }
            default -> {
                return NODES.textNode(p.getText());
            }
        }
    }

    /**
     * The text to write back for the current number or boolean: its spelling, unless an explicit tag made
     * it a type its plain text would not read back as ({@code !!float 1} would read back as an integer).
     * The YAML generator writes no scalar tag, so such a value is written in its canonical form instead,
     * which keeps its type and value.
     */
    private static String writtenText(JsonParser p) throws IOException {
        String text = p.getText();
        if (p.getTypeId() == null || impliedToken(text) == p.currentToken()) {
            return text;
        }
        return p.currentToken().isNumeric() ? String.valueOf(p.getNumberValue()) : String.valueOf(p.getBooleanValue());
    }

    /**
     * The current number's value: a float as its exact decimal, as the typed binding read it (a time of
     * {@code 1730000000.123456789} keeps its nanoseconds), or null where the parser has no number for it
     * ({@code .nan}, {@code .inf}), so it binds as its spelling.
     */
    private static Number numberOf(JsonParser p) {
        try {
            return p.currentToken() == JsonToken.VALUE_NUMBER_FLOAT ? p.getDecimalValue() : p.getNumberValue();
        } catch (IOException | NumberFormatException e) {
            return null;
        }
    }

    /** The token YAML infers for a plain scalar with this text and no tag. */
    private static JsonToken impliedToken(String text) throws IOException {
        try (JsonParser plain = PLAIN.createParser("- " + text)) {
            plain.nextToken();
            return plain.nextToken();
        }
    }

    private static final YAMLFactory PLAIN = new YAMLFactory();

    /**
     * The node to bind. A plain number binds as the typed binding bound it: as its number for an enum or
     * time field ({@code environment: +2} is {@code PRODUCTION}) and as its spelling for a string field
     * ({@code payerId: 1.10} is "1.10"), through a numeric node whose number prints as the spelling. A
     * plain boolean binds as its spelling.
     */
    static JsonNode forBinding(JsonNode node) {
        if (node instanceof PlainScalar plain) {
            return plain.forBinding();
        }
        if (node.isObject()) {
            ObjectNode copy = NODES.objectNode();
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                copy.set(field.getKey(), forBinding(field.getValue()));
            }
            return copy;
        }
        if (node.isArray()) {
            ArrayNode copy = NODES.arrayNode();
            node.forEach(item -> copy.add(forBinding(item)));
            return copy;
        }
        return node;
    }

    /**
     * A number whose {@link #toString()} is the YAML spelling: Jackson binds a string field from a numeric
     * node through its number's text, so this gives it the spelling, as the typed binding did.
     */
    static final class SpelledNumber extends Number {
        private static final long serialVersionUID = 1L;

        private final String text;
        private final Number value;

        SpelledNumber(String text, Number value) {
            this.text = text;
            this.value = value;
        }

        @Override
        public int intValue() {
            return value.intValue();
        }

        @Override
        public long longValue() {
            return value.longValue();
        }

        @Override
        public float floatValue() {
            return value.floatValue();
        }

        @Override
        public double doubleValue() {
            return value.doubleValue();
        }

        @Override
        public String toString() {
            return text;
        }
    }

    /**
     * A YAML plain number or boolean. It binds as its spelling (with its value, for a number) and is written
     * back unquoted as its written text, which is the spelling unless a tag needs a canonical form.
     */
    static final class PlainScalar extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonToken token;
        private final String spelling;
        private final String text;
        private final transient Number value;

        PlainScalar(JsonToken token, String text, Number value) {
            this(token, text, text, value);
        }

        PlainScalar(JsonToken token, String spelling, String written, Number value) {
            this.token = token;
            this.spelling = spelling;
            this.text = written;
            this.value = value;
        }

        private JsonNode forBinding() {
            if (value == null) {
                return NODES.textNode(spelling);
            }
            Number spelled = new SpelledNumber(spelling, value);
            if (value instanceof BigInteger big) {
                return new BigIntegerNode(big) {
                    @Override
                    public Number numberValue() {
                        return spelled;
                    }
                };
            }
            if (token == JsonToken.VALUE_NUMBER_INT) {
                return new LongNode(value.longValue()) {
                    @Override
                    public Number numberValue() {
                        return spelled;
                    }
                };
            }
            return new DecimalNode((BigDecimal) value) {
                @Override
                public Number numberValue() {
                    return spelled;
                }
            };
        }

        @Override
        public JsonToken asToken() {
            return token;
        }

        @Override
        public JsonNodeType getNodeType() {
            return token.isBoolean() ? JsonNodeType.BOOLEAN : JsonNodeType.NUMBER;
        }

        @Override
        public String asText() {
            return spelling;
        }

        @Override
        public void serialize(JsonGenerator g, SerializerProvider provider) throws IOException {
            // The YAML generator writes an encoded number as a plain, unquoted scalar: the text as it was read.
            g.writeNumber(text);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof PlainScalar other && token == other.token && spelling.equals(other.spelling)
                    && text.equals(other.text);
        }

        @Override
        public int hashCode() {
            return Objects.hash(token, spelling, text);
        }
    }
}
