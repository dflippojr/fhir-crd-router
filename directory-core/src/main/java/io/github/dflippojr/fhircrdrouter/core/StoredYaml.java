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
import com.fasterxml.jackson.databind.node.ContainerNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.databind.node.ValueNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.events.AliasEvent;
import org.yaml.snakeyaml.events.CollectionStartEvent;
import org.yaml.snakeyaml.events.Event;
import org.yaml.snakeyaml.events.MappingStartEvent;
import org.yaml.snakeyaml.events.NodeEvent;
import org.yaml.snakeyaml.events.ScalarEvent;
import org.yaml.snakeyaml.events.SequenceStartEvent;
import org.yaml.snakeyaml.parser.Parser;
import org.yaml.snakeyaml.parser.ParserImpl;
import org.yaml.snakeyaml.reader.StreamReader;
import org.yaml.snakeyaml.reader.UnicodeReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * The connection file as a tree that keeps each unquoted scalar as it was spelled (#231).
 *
 * <p>Jackson's own tree turns a YAML plain scalar into a number or boolean node, which loses its text:
 * {@code payerId: 1.10} becomes 1.1, and a rewrite of the tree would store the changed value. Here a
 * plain number or boolean is a {@link PlainScalar} holding its text, written back unquoted as it was
 * read. This tree is only what a rewrite writes; records are bound from the YAML parser itself.
 *
 * <p>A rewrite writes back only a plain tree: mappings, sequences and scalars, with no anchor, alias, explicit
 * tag or duplicate key (#231, owner decision: an allowlist). {@link #allowlist} reads the file's YAML events and
 * wraps every value outside it in an {@link Unwritable}, which the store refuses to write.
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

    /**
     * Reads the value at the parser's current token. A duplicate key keeps its last value, in its first place;
     * {@link #allowlist} marks it.
     */
    static JsonNode read(JsonParser p) throws IOException {
        JsonToken token = p.currentToken();
        return switch (token) {
            case START_OBJECT -> {
                ObjectNode object = NODES.objectNode();
                while (p.nextToken() == JsonToken.FIELD_NAME) {
                    String name = p.currentName();
                    p.nextToken();
                    object.set(name, read(p));
                }
                yield object;
            }
            case START_ARRAY -> {
                ArrayNode array = NODES.arrayNode();
                while (p.nextToken() != JsonToken.END_ARRAY) {
                    array.add(read(p));
                }
                yield array;
            }
            case VALUE_NULL -> NODES.nullNode();
            case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT, VALUE_TRUE, VALUE_FALSE -> {
                String text = p.getText();
                yield new PlainScalar(token, text, writtenBackAsRead(token, text));
            }
            // The YAML parser's only embedded value is !!binary, which is tagged, so never written back.
            case VALUE_EMBEDDED_OBJECT -> NODES.binaryNode(p.getBinaryValue());
            default -> NODES.textNode(p.getText());
        };
    }

    private static final YAMLFactory PLAIN = new YAMLFactory();

    /** Where a value outside the plain tree sits: the entry's index, then field names and item indexes. */
    private record Found(List<Object> path, String reason) { }

    /**
     * Wraps every value of this file's list that is outside the plain tree in an {@link Unwritable}, and answers
     * what keeps the document as a whole from being written back, or null. The check reads the YAML events
     * themselves: Jackson's parser does not report every anchor and tag (a scalar's anchor, a key's tag), and
     * the check must allow what it knows rather than refuse what Jackson happens to show.
     *
     * <p>An entry stays writable only while each of its events is a mapping, a sequence or a scalar with no
     * anchor and no tag, and no mapping repeats a key. An alias, or anything else, makes the value holding it
     * unwritable; a tag or anchor on a key makes that key's value unwritable. The store has already read
     * {@code root} as the file's list; should the events ever not match it, the whole document is refused.
     */
    static String allowlist(ArrayNode root, byte[] bytes) {
        try {
            Parser events = new ParserImpl(
                    new StreamReader(new UnicodeReader(new ByteArrayInputStream(bytes))), new LoaderOptions());
            events.getEvent(); // stream start
            events.getEvent(); // document start
            String reason = notPlain((SequenceStartEvent) events.getEvent()); // the store has read a list
            List<Found> found = new ArrayList<>();
            for (int index = 0; !events.checkEvent(Event.ID.SequenceEnd); index++) {
                walk(events, List.of(index), found);
            }
            events.getEvent(); // sequence end
            events.getEvent(); // document end
            if (reason == null && !events.checkEvent(Event.ID.StreamEnd)) {
                reason = "a second YAML document"; // never read, so a rewrite would drop it
            }
            for (Found value : found) {
                int index = (Integer) value.path().get(0);
                root.set(index, wrapped(root.get(index), value.path(), 1, value.reason()));
            }
            return reason;
        } catch (RuntimeException e) {
            return "YAML the rewrite could not check";
        }
    }

    /** Walks one value's events, noting each value outside the plain tree in document order. */
    private static void walk(Parser events, List<Object> path, List<Found> found) {
        Event event = events.getEvent();
        String reason = notPlain(event);
        if (reason != null) {
            found.add(new Found(path, reason));
        }
        if (event instanceof MappingStartEvent) {
            Set<String> keys = new HashSet<>();
            while (!events.checkEvent(Event.ID.MappingEnd)) {
                ScalarEvent key = (ScalarEvent) events.getEvent(); // Jackson has read every key as a scalar
                List<Object> value = append(path, key.getValue());
                String keyReason = notPlain(key);
                if (keyReason != null) {
                    found.add(new Found(value, keyReason + " on its key"));
                }
                if (!keys.add(key.getValue())) {
                    found.add(new Found(value, "a duplicate key"));
                }
                walk(events, value, found);
            }
            events.getEvent();
        } else if (event instanceof SequenceStartEvent) {
            for (int i = 0; !events.checkEvent(Event.ID.SequenceEnd); i++) {
                walk(events, append(path, i), found);
            }
            events.getEvent();
        }
    }

    private static List<Object> append(List<Object> path, Object segment) {
        List<Object> longer = new ArrayList<>(path);
        longer.add(segment);
        return longer;
    }

    /**
     * Why this value's own event is outside the plain tree, or null where it is a plain one. A value's event is
     * an alias, a scalar or a mapping or sequence start; any other fails the cast, and the document is refused.
     */
    private static String notPlain(Event event) {
        if (event instanceof AliasEvent) {
            return "a YAML alias";
        }
        if (((NodeEvent) event).getAnchor() != null) {
            return "a YAML anchor";
        }
        String tag = event instanceof ScalarEvent scalar ? scalar.getTag() : ((CollectionStartEvent) event).getTag();
        return tag == null ? null : "a YAML tag";
    }

    /**
     * The node with the value at {@code path} (from {@code depth} on) wrapped. A duplicate key's tree keeps only
     * its last value, so a path into an earlier one may leave the tree; the node where it does is wrapped.
     */
    private static JsonNode wrapped(JsonNode node, List<Object> path, int depth, String reason) {
        if (node instanceof Unwritable) {
            return node;
        }
        if (depth == path.size() || !(node instanceof ContainerNode<?>)) {
            return new Unwritable(node, reason);
        }
        Object segment = path.get(depth);
        JsonNode child = segment instanceof Integer i ? node.get(i) : node.get((String) segment);
        if (child == null) {
            return new Unwritable(node, reason);
        }
        JsonNode replaced = wrapped(child, path, depth + 1, reason);
        if (node instanceof ObjectNode object) {
            object.set((String) segment, replaced);
        } else {
            ((ArrayNode) node).set((Integer) segment, replaced);
        }
        return node;
    }

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
     * One value in a node that the writer cannot write back as it was read, by path (a field name, with
     * {@code .name} and {@code [index]} for nested values; empty for the node itself). {@code
     * boundValueKeepsBinding} is true for a leading-zero number, which the store may replace with its field's
     * bound value; every other problem is refused.
     */
    record Problem(String path, String reason, boolean boundValueKeepsBinding) {
        /** The top-level field the path is in. */
        String field() {
            return path.split("[.\\[]", 2)[0];
        }
    }

    /** Every value in this node the writer cannot write back as read, in document order. */
    static List<Problem> problems(JsonNode node) {
        List<Problem> problems = new ArrayList<>();
        collect(node, "", problems);
        return problems;
    }

    private static void collect(JsonNode node, String path, List<Problem> problems) {
        if (node instanceof Unwritable unwritable) {
            problems.add(new Problem(path, unwritable.reason, false));
        } else if (node instanceof PlainScalar plain) {
            if (!plain.writtenAsRead) {
                problems.add(new Problem(path, "a number with a leading zero", true));
            }
        } else if (node.isObject()) {
            for (Map.Entry<String, JsonNode> field : node.properties()) {
                collect(field.getValue(), path.isEmpty() ? field.getKey() : path + "." + field.getKey(), problems);
            }
        } else {
            for (int i = 0; i < node.size(); i++) {
                collect(node.get(i), path + "[" + i + "]", problems);
            }
        }
    }

    /**
     * A value outside the plain tree, which the writer cannot write back as read: it holds an anchor, an alias or
     * an explicit tag, or it is one of several values for a duplicate key. The store refuses to write it; if it
     * ever were written, it fails rather than write the wrapped value without what made it unwritable.
     */
    static final class Unwritable extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonNode value;
        private final String reason;

        Unwritable(JsonNode value, String reason) {
            this.value = value;
            this.reason = reason;
        }

        @Override
        public JsonToken asToken() {
            return JsonToken.VALUE_EMBEDDED_OBJECT;
        }

        @Override
        public JsonNodeType getNodeType() {
            return JsonNodeType.POJO;
        }

        @Override
        public String asText() {
            return value.asText();
        }

        @Override
        public void serialize(JsonGenerator g, SerializerProvider provider) throws IOException {
            throw new IOException("refusing to write " + reason + "; the store refuses such a write before this");
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Unwritable other && value.equals(other.value) && reason.equals(other.reason);
        }

        @Override
        public int hashCode() {
            return Objects.hash(value, reason);
        }
    }

    /**
     * A YAML plain number or boolean, written back unquoted as it was spelled. Records are bound from the
     * parser, never from this node.
     *
     * <p>The generator quotes a number with a leading zero, so {@code 010} (octal 8) would come back as the
     * string {@code '010'}; such a node is marked, and the store writes the field's bound value instead, or
     * refuses where it has none (#231). A tagged number is never a plain scalar: {@link #allowlist} wraps it.
     */
    static final class PlainScalar extends ValueNode {
        private static final long serialVersionUID = 1L;

        private final JsonToken token;
        private final String text;
        private final boolean writtenAsRead;

        PlainScalar(JsonToken token, String text) {
            this(token, text, true);
        }

        PlainScalar(JsonToken token, String text, boolean writtenAsRead) {
            this.token = token;
            this.text = text;
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
