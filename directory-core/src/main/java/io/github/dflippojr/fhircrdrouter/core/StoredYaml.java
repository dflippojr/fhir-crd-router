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
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.List;
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
                return new PlainScalar(token, text, p.getTypeId() != null && impliedToken(text) != token,
                        writtenBackAsRead(token, text));
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
     * Whether the generator writes this number or boolean so that it reads back as the same token and text.
     * It does not for a number with a leading zero: YAML reads {@code 010} as the octal 8, and the generator
     * writes it back quoted, as the string {@code '010'}.
     */
    private static boolean writtenBackAsRead(JsonToken token, String text) throws IOException {
        StringWriter out = new StringWriter();
        try (JsonGenerator g = PLAIN.createGenerator(out)) {
            g.writeStartArray();
            g.writeNumber(text);
            g.writeEndArray();
        }
        try (JsonParser p = PLAIN.createParser(out.toString())) {
            p.nextToken();
            return p.nextToken() == token && text.equals(p.getText());
        }
    }

    /**
     * The paths in this node of numbers or booleans the generator would not write back as read, other than
     * those with a disagreeing tag ({@link #droppedTagPath}), in document order.
     */
    static List<String> unkeptPaths(JsonNode node) {
        List<String> paths = new ArrayList<>();
        collectUnkept(node, "", paths);
        return paths;
    }

    private static void collectUnkept(JsonNode node, String path, List<String> paths) {
        if (node instanceof PlainScalar plain) {
            if (!plain.tagDisagrees && !plain.writtenAsRead) {
                paths.add(path);
            }
        } else if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                collectUnkept(field.getValue(), path.isEmpty() ? field.getKey() : path + "." + field.getKey(), paths);
            }
        } else {
            for (int i = 0; i < node.size(); i++) {
                collectUnkept(node.get(i), path + "[" + i + "]", paths);
            }
        }
    }

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
     * write it (#231). It also quotes a number with a leading zero, so {@code 010} (octal 8) would come back
     * as the string {@code '010'}; such a node is marked too, and the store writes the field's bound value
     * instead, or refuses where it has none.
     */
    static final class PlainScalar extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonToken token;
        private final String text;
        private final boolean tagDisagrees;
        private final boolean writtenAsRead;

        PlainScalar(JsonToken token, String text) {
            this(token, text, false, true);
        }

        PlainScalar(JsonToken token, String text, boolean tagDisagrees, boolean writtenAsRead) {
            this.token = token;
            this.text = text;
            this.tagDisagrees = tagDisagrees;
            this.writtenAsRead = writtenAsRead;
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
