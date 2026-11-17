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
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import java.io.IOException;
import java.util.Map;
import java.util.Objects;

/**
 * The connection file as a tree that keeps each unquoted scalar as it was spelled (#231).
 *
 * <p>Jackson's own tree turns a YAML plain scalar into a number or boolean node, which loses its text:
 * {@code payerId: 1.10} becomes 1.1, and a rewrite of the tree would store the changed value. Here a
 * plain number or boolean is a {@link PlainScalar} holding its text, written back unquoted as it was
 * read. This tree is only what a rewrite writes; records are bound from the YAML parser itself.
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
                String text = p.getText();
                return new PlainScalar(token, text, p.getTypeId() != null && impliedToken(text) != token);
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

    /** The token YAML infers for a plain scalar with this text and no tag. */
    private static JsonToken impliedToken(String text) throws IOException {
        try (JsonParser plain = PLAIN.createParser("- " + text)) {
            plain.nextToken();
            return plain.nextToken();
        }
    }

    private static final YAMLFactory PLAIN = new YAMLFactory();

    /**
     * Where in this node a rewrite would drop a tag that disagrees with its plain text (a field name, with
     * {@code .name} and {@code [index]} for nested values), or null when there is none.
     */
    static String droppedTagPath(JsonNode node, String path) {
        if (node instanceof PlainScalar plain) {
            return plain.tagDisagrees ? path : null;
        }
        if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                String found = droppedTagPath(field.getValue(), path.isEmpty() ? field.getKey() : path + "." + field.getKey());
                if (found != null) {
                    return found;
                }
            }
        }
        for (int i = 0; i < node.size() && node.isArray(); i++) {
            String found = droppedTagPath(node.get(i), path + "[" + i + "]");
            if (found != null) {
                return found;
            }
        }
        return null;
    }

    /**
     * A YAML plain number or boolean, written back unquoted as it was spelled. Records are bound from the
     * parser, never from this node.
     *
     * <p>The generator writes no scalar tag, so a tag that disagrees with the plain text ({@code !!float 1},
     * whose text alone reads as an integer) would be lost; such a node is marked, and the store refuses to
     * write it (#231). It also quotes a number with a leading zero, so {@code 007} comes back as the string
     * {@code '007'}, which binds as before: a string field gets the same text, and a number field the same
     * value.
     */
    static final class PlainScalar extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonToken token;
        private final String text;
        private final boolean tagDisagrees;

        PlainScalar(JsonToken token, String text) {
            this(token, text, false);
        }

        PlainScalar(JsonToken token, String text, boolean tagDisagrees) {
            this.token = token;
            this.text = text;
            this.tagDisagrees = tagDisagrees;
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
