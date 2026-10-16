package io.github.dflippojr.fhircrdrouter.client.testsupport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Tuple;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.List;
import java.util.Map;

/** Generators for JSON values and the strings in them, shared by the property tests. */
public final class JsonArbitraries {

    private static final JsonNodeFactory NODES = JsonNodeFactory.instance;

    /** Field names the SDK reads somewhere, so generated objects often hit a real code path. */
    private static final List<String> KNOWN_FIELDS = List.of(
            "services", "hook", "id", "title", "description", "prefetch",
            "cards", "systemActions", "uuid", "summary", "detail", "indicator", "source", "label", "url",
            "topic", "system", "code", "display", "suggestions", "selectionBehavior", "links",
            "type", "resource", "resourceId",
            "access_token", "expires_in", "token_type", "scope", "error", "error_description");

    private JsonArbitraries() { }

    /**
     * Well-formed Unicode text: ASCII (with the URL and JSON metacharacters), the rest of the BMP and
     * supplementary code points, but never a lone surrogate, which no encoder can send faithfully.
     */
    public static Arbitrary<String> text() {
        Arbitrary<String> ascii = Arbitraries.strings().withCharRange(' ', '~').ofMaxLength(16);
        Arbitrary<String> metacharacters = Arbitraries.strings().withChars("./?#%&=+;:@ \\\"'{}[]\t\n\u0000")
                .withCharRange('a', 'c').ofMaxLength(8);
        Arbitrary<String> bmp = Arbitraries.strings().withCharRange('\u0000', '퟿').withCharRange('', '￿')
                .ofMaxLength(8);
        Arbitrary<String> supplementary = Arbitraries.integers().between(0x10000, Character.MAX_CODE_POINT)
                .map(Character::toString).list().ofMaxSize(3).map(parts -> String.join("", parts));
        return Arbitraries.oneOf(ascii, metacharacters, bmp, supplementary,
                Arbitraries.of("", " ", ".", "..", "null", "3600", "-1", "1e999", "%2e%2e", "../x"));
    }

    /** Any JSON value, nested at most {@code depth} levels. */
    public static Arbitrary<JsonNode> value(int depth) {
        if (depth <= 0) {
            return scalar();
        }
        Arbitrary<JsonNode> child = value(depth - 1);
        Arbitrary<JsonNode> array = child.list().ofMaxSize(4).map(JsonArbitraries::array);
        Arbitrary<JsonNode> object = Arbitraries.maps(fieldName(), child).ofMaxSize(4).map(JsonArbitraries::object);
        return Arbitraries.frequencyOf(
                Tuple.of(4, scalar()),
                Tuple.of(1, array),
                Tuple.of(1, object));
    }

    /** Any scalar, weighted towards the values that broke number and string handling before. */
    public static Arbitrary<JsonNode> scalar() {
        return Arbitraries.oneOf(
                Arbitraries.just(NODES.nullNode()),
                Arbitraries.of(true, false).map(NODES::booleanNode),
                Arbitraries.integers().map(NODES::numberNode),
                Arbitraries.longs().map(NODES::numberNode),
                Arbitraries.of(Long.MAX_VALUE, Long.MIN_VALUE, 0L, -1L, 1L, 30L, 3600L, 86_400L * 366)
                        .map(NODES::numberNode),
                Arbitraries.bigIntegers().between(BigInteger.TWO.pow(63), BigInteger.TWO.pow(200))
                        .map(NODES::numberNode),
                Arbitraries.doubles().map(NODES::numberNode),
                Arbitraries.of(1e308, -1e308, 3600.5, 0.5, -0.0).map(NODES::numberNode),
                Arbitraries.of(new BigDecimal("1e400"), new BigDecimal("3600.000")).map(NODES::numberNode),
                text().map(NODES::textNode));
    }

    /** A field name: usually one the SDK reads, sometimes any text. */
    public static Arbitrary<String> fieldName() {
        return Arbitraries.frequencyOf(
                Tuple.of(3, Arbitraries.of(KNOWN_FIELDS)),
                Tuple.of(1, text()));
    }

    /** An object with the given fields, each either absent or any value. */
    public static Arbitrary<JsonNode> objectWith(List<String> fields, int depth) {
        Arbitrary<JsonNode> absentOrValue = Arbitraries.frequencyOf(
                Tuple.of(1, Arbitraries.just((JsonNode) null)),
                Tuple.of(3, value(depth)));
        return absentOrValue.list().ofSize(fields.size()).map(values -> {
            ObjectNode node = NODES.objectNode();
            for (int i = 0; i < fields.size(); i++) {
                if (values.get(i) != null) {
                    node.set(fields.get(i), values.get(i));
                }
            }
            return node;
        });
    }

    public static ArrayNode array(List<JsonNode> items) {
        ArrayNode node = NODES.arrayNode();
        items.forEach(node::add);
        return node;
    }

    public static ObjectNode object(Map<String, JsonNode> fields) {
        ObjectNode node = NODES.objectNode();
        fields.forEach(node::set);
        return node;
    }
}
