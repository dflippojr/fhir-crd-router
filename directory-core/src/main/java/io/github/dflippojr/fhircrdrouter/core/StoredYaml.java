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
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ValueNode;

import java.io.IOException;
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
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT, VALUE_TRUE, VALUE_FALSE -> {
                return new PlainScalar(token, p.getText());
            }
            default -> {
                // A string, or anything else YAML can hold (such as !!binary), as its text.
                return NODES.textNode(p.getText());
            }
        }
    }

    /**
     * The node to bind: a copy with every {@link PlainScalar} as a text node, so a string field gets the
     * scalar's spelling, as the typed binding gave it. Enum and time fields accept the text as they
     * accepted the number ({@code environment: 2} is still {@code PRODUCTION}).
     */
    static JsonNode forBinding(JsonNode node) {
        if (node instanceof PlainScalar plain) {
            return NODES.textNode(plain.text);
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

    /** A YAML plain number or boolean, kept as its text and written back unquoted as it was read. */
    static final class PlainScalar extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonToken token;
        private final String text;

        PlainScalar(JsonToken token, String text) {
            this.token = token;
            this.text = text;
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
            return text;
        }

        @Override
        public void serialize(JsonGenerator g, SerializerProvider provider) throws IOException {
            // The YAML generator writes an encoded number as a plain, unquoted scalar: the text as it was read.
            g.writeNumber(text);
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof PlainScalar other && token == other.token && text.equals(other.text);
        }

        @Override
        public int hashCode() {
            return Objects.hash(token, text);
        }
    }
}
