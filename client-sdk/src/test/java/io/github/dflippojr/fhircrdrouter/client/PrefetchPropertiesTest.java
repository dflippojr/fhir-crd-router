package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdPrefetch;
import io.github.dflippojr.fhircrdrouter.client.testsupport.JsonArbitraries;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer;
import io.github.dflippojr.fhircrdrouter.client.testsupport.LoopbackPayer.Reply;
import io.github.dflippojr.fhircrdrouter.core.AuthType;
import io.github.dflippojr.fhircrdrouter.core.ConnectionRecord;
import io.github.dflippojr.fhircrdrouter.core.CredentialProvider;
import io.github.dflippojr.fhircrdrouter.core.Environment;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Combinators;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.lifecycle.AfterContainer;
import net.jqwik.api.lifecycle.BeforeContainer;

import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Prefetch maps reach the payer as CDS Hooks 2.0 requires, null "no data" values included (the #66
 * class), and template expansion never throws or lets a context value add query syntax. That a
 * context value never becomes a {@code .} or {@code ..} segment is #108. That it never adds a FHIR search OR
 * value or a {@code |} or {@code $} split is #160.
 */
class PrefetchPropertiesTest {

    /** Fixed so CI is reproducible; jqwik prints the seed and the shrunk sample on failure. */
    private static final String SEED = "98066";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    /** Reads what the payer received without rounding: 1E+400 must not come back as Infinity. */
    private static final ObjectMapper EXACT = new ObjectMapper()
            .enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS)
            .enable(DeserializationFeature.USE_BIG_INTEGER_FOR_INTS);
    private static final HttpClient HTTP = HttpClient.newHttpClient();
    private static final CredentialProvider NO_CREDENTIALS = new CredentialProvider() {
        @Override public Optional<String> resolve(String credentialRef) { return Optional.empty(); }
        @Override public void put(String credentialRef, String secretValue) { }
        @Override public void remove(String credentialRef) { }
    };
    /** Characters that would change a FHIR query's structure if a context value inserted them. */
    private static final String QUERY_SYNTAX = "/?&=#+ ";
    /** JSON numbers compare by value: a long or double the payer parses back comes back as a big number. */
    private static final Comparator<JsonNode> NUMBERS_BY_VALUE = (a, b) -> a.equals(b)
            || (a.isNumber() && b.isNumber() && a.decimalValue().compareTo(b.decimalValue()) == 0) ? 0 : 1;

    private static final List<String> KNOWN_CONTEXT_FIELDS = List.of("patientId", "encounterId", "userId", "draftOrders");
    private static final Object ABSENT = new Object();

    private static LoopbackPayer payer;

    @BeforeContainer
    static void start() {
        payer = new LoopbackPayer();
    }

    @AfterContainer
    static void stop() {
        payer.close();
    }

    @Property(seed = SEED)
    void everyPrefetchKeyReachesThePayerWithItsValueOrNull(@ForAll("prefetch") Map<String, JsonNode> prefetch)
            throws Exception {
        payer.reset(request -> new Reply(200, "{\"cards\":[]}"));
        CrdPrefetch.Builder builder = CrdPrefetch.builder();
        prefetch.forEach(builder::put);
        CdsHookRequest request = new CdsHookRequest("order-sign", "instance", Map.of("patientId", "p"), builder.build());
        ConnectionRecord record = ConnectionRecord.builder().payerId("P").environment(Environment.SANDBOX)
                .baseUrl(payer.origin()).authType(AuthType.NONE).build();

        new CdsHooksClient(HTTP, NO_CREDENTIALS).callHookRaw(record, "svc", request);

        JsonNode sent = EXACT.readTree(payer.received().get(0).body());
        if (prefetch.isEmpty()) {
            assertFalse(sent.has("prefetch"), sent.toString());
            return;
        }
        JsonNode sentPrefetch = sent.get("prefetch");
        assertTrue(sentPrefetch.isObject(), sent.toString());
        List<String> sentKeys = new ArrayList<>();
        sentPrefetch.fieldNames().forEachRemaining(sentKeys::add);
        assertEquals(new ArrayList<>(prefetch.keySet()), sentKeys);
        prefetch.forEach((key, value) -> {
            JsonNode actual = sentPrefetch.get(key);
            if (value == null || value.isNull()) {
                assertTrue(actual.isNull(), key + " -> " + actual);
            } else {
                assertTrue(value.equals(NUMBERS_BY_VALUE, actual), key + ": " + value + " sent as " + actual);
            }
        });
    }

    @Property(seed = SEED)
    void expansionNeverThrowsAndAccountsForEveryKey(@ForAll("templates") Map<String, String> templates,
                                                    @ForAll("contexts") Map<String, Object> context) {
        CdsHookRequest request = new CdsHookRequest("order-sign", "instance", context, null);

        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(templates, request);

        Set<String> accounted = new LinkedHashSet<>(expansion.queries().keySet());
        expansion.unresolved().keySet().forEach(key -> assertTrue(accounted.add(key), "in both maps: " + key));
        assertEquals(templates.keySet(), accounted);
        expansion.queries().forEach((key, query) -> {
            String literal = templates.get(key).replaceAll("(?s)\\{\\{.*?}}", "");
            for (char c : QUERY_SYNTAX.toCharArray()) {
                assertEquals(count(literal, c), count(query, c),
                        "'" + c + "' count changed: " + templates.get(key) + " -> " + query);
            }
        });
    }

    @Property(seed = SEED)
    void contextValuesNeverBecomeDotSegments(@ForAll("templates") Map<String, String> templates,
                                             @ForAll("contexts") Map<String, Object> context) {
        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(templates,
                new CdsHookRequest("order-sign", "instance", context, null));
        expansion.queries().forEach((key, query) -> {
            String literal = templates.get(key).replaceAll("(?s)\\{\\{.*?}}", "");
            long dotSegments = Arrays.stream(query.split("[/?&=]", -1)).filter(s -> s.equals(".") || s.equals("..")).count();
            long literalDotSegments = Arrays.stream(literal.split("[/?&=]", -1)).filter(s -> s.equals(".") || s.equals("..")).count();
            assertEquals(literalDotSegments, dotSegments, templates.get(key) + " -> " + query);
        });
    }

    /** An empty id is ignored by a FHIR server, so {@code Coverage?patient=} would match every patient (#155). */
    @Property(seed = SEED)
    void templatesReferencingABlankContextFieldAreUnresolved(@ForAll("templates") Map<String, String> templates,
                                                             @ForAll("contexts") Map<String, Object> context,
                                                             @ForAll("blankFields") String field,
                                                             @ForAll("blanks") String blank) {
        Map<String, Object> withBlank = new LinkedHashMap<>(context);
        withBlank.put(field, blank);
        Map<String, String> withReference = new LinkedHashMap<>(templates);
        withReference.put("referencesBlank", "X/{{context." + field + "}}");
        Pattern reference = Pattern.compile("\\{\\{\\s*(context\\." + field
                + (field.equals("userId") ? "|user(Practitioner|PractitionerRole|Patient|RelatedPerson)Id" : "")
                + ")\\s*}}");

        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(withReference,
                new CdsHookRequest("order-sign", "instance", withBlank, null));

        withReference.forEach((key, template) -> {
            if (template != null && reference.matcher(template).find()) {
                assertTrue(expansion.unresolved().containsKey(key), template + " -> " + expansion.queries().get(key));
            }
        });
    }

    @Property(seed = SEED)
    void userTokensWithABlankIdAreUnresolved(@ForAll("blanks") String blank) {
        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(
                Map.of("practitioner", "Practitioner/{{userPractitionerId}}"),
                new CdsHookRequest("order-sign", "instance", Map.of("userId", "Practitioner/" + blank), null));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
    }

    /**
     * Reads a query value the way a FHIR server does (https://hl7.org/fhir/R4/search.html#escaping): URL-decode,
     * then split on unescaped {@code ,} and look for unescaped {@code |} and {@code $}. The value must come back as
     * one OR value equal to the context value, with no separator (#160).
     */
    @Property(seed = SEED)
    void contextValuesNeverAddAnOrValueOrASeparatorToASearchParameter(@ForAll("searchSyntaxValues") String value) {
        Map<String, String> templates = Map.of(
                "coverage", "Coverage?patient={{context.patientId}}&status=active",
                "observation", "Observation?subject=Patient/x&code={{context.patientId}}");

        PrefetchTemplates.Expansion expansion = PrefetchTemplates.expand(templates,
                new CdsHookRequest("order-sign", "instance", Map.of("patientId", value), null));

        assertEquals(templates.keySet(), expansion.queries().keySet(), expansion.unresolved().toString());
        assertEquals(List.of(value), searchValues(expansion.queries().get("coverage"), "patient"));
        assertEquals(List.of(value), searchValues(expansion.queries().get("observation"), "code"));
    }

    /** The OR values of {@code parameter}, unescaped; fails on an unescaped {@code |} or {@code $}. */
    private static List<String> searchValues(String query, String parameter) {
        String queryString = query.substring(query.indexOf('?') + 1);
        List<String> raw = Arrays.stream(queryString.split("&", -1))
                .filter(pair -> pair.startsWith(parameter + "="))
                .map(pair -> URLDecoder.decode(pair.substring(parameter.length() + 1), StandardCharsets.UTF_8))
                .toList();
        assertEquals(1, raw.size(), query);
        List<String> values = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        String text = raw.get(0);
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == '\\') {
                assertTrue(i + 1 < text.length(), "dangling escape: " + query);
                current.append(text.charAt(++i));
            } else if (c == ',') {
                values.add(current.toString());
                current.setLength(0);
            } else {
                assertFalse(c == '|' || c == '$', "unescaped '" + c + "': " + query);
                current.append(c);
            }
        }
        values.add(current.toString());
        return values;
    }

    private static long count(String s, char c) {
        return s.chars().filter(ch -> ch == c).count();
    }

    @Provide
    Arbitrary<Map<String, JsonNode>> prefetch() {
        Arbitrary<JsonNode> value = Arbitraries.frequencyOf(
                Tuple.of(1, Arbitraries.just((JsonNode) null)),
                Tuple.of(4, JsonArbitraries.value(3)));
        return Arbitraries.maps(JsonArbitraries.text(), value).ofMaxSize(5).map(LinkedHashMap::new);
    }

    /** Templates built from FHIR query text, prefetch tokens (valid and not) and stray braces. */
    @Provide
    Arbitrary<Map<String, String>> templates() {
        Arbitrary<String> part = Arbitraries.frequencyOf(
                Tuple.of(3, Arbitraries.of("Patient/", "Coverage?patient=", "&status=active", "Encounter/", "?_id=",
                        "/", "Practitioner/", "&_include=x")),
                Tuple.of(3, Arbitraries.of("{{context.patientId}}", "{{ context.encounterId }}", "{{context.userId}}",
                        "{{userPractitionerId}}", "{{userPatientId}}", "{{userPractitionerRoleId}}",
                        "{{userRelatedPersonId}}", "{{context.draftOrders}}", "{{context.a.b}}", "{{unknown}}",
                        "{{context.}}", "{{", "}}", "{{}}")),
                Tuple.of(1, JsonArbitraries.text()));
        Arbitrary<String> template = part.list().ofMaxSize(5).map(parts -> String.join("", parts));
        Arbitrary<String> templateOrNull = Arbitraries.frequencyOf(
                Tuple.of(1, Arbitraries.just((String) null)),
                Tuple.of(9, template));
        return Arbitraries.maps(JsonArbitraries.text(), templateOrNull).ofMaxSize(4).map(LinkedHashMap::new);
    }

    /** Strings of ASCII and Unicode spaces (no-break, figure, zero-width, ideographic), the empty string included. */
    @Provide
    Arbitrary<String> blanks() {
        return Arbitraries.strings().withChars(' ', '\t', '\u00A0', '\u2007', '\u200B', '\u3000')
                .ofMinLength(0).ofMaxLength(6);
    }

    /** Text with at least one FHIR search escape or separator character in it. */
    @Provide
    Arbitrary<String> searchSyntaxValues() {
        Arbitrary<String> syntax = Arbitraries.strings().withChars(',', '|', '$', '\\').ofMinLength(1).ofMaxLength(4);
        Arbitrary<String> text = Arbitraries.frequencyOf(
                Tuple.of(1, Arbitraries.just("")),
                Tuple.of(2, Arbitraries.of("pat-1", "http://loinc.org", "Patient/p", " ", "a b")),
                Tuple.of(2, JsonArbitraries.text()));
        return Combinators.combine(text, syntax, text, syntax, text).as((a, b, c, d, e) -> a + b + c + d + e);
    }

    @Provide
    Arbitrary<String> blankFields() {
        return Arbitraries.of("patientId", "encounterId", "userId");
    }

    /** Context maps that usually hold the fields templates read, with any JSON-ish value, plus other fields. */
    @Provide
    Arbitrary<Map<String, Object>> contexts() {
        Arbitrary<Object> value = Arbitraries.frequencyOf(
                Tuple.of(2, JsonArbitraries.text()),
                Tuple.of(3, Arbitraries.of("p-1", ".", "..", "...", "a.b", "Practitioner/abc", "Patient/p-1",
                        "PractitionerRole/", "RelatedPerson/a/b", "Practitioner/a b?c=d", "Patient/.", "Patient/..")),
                Tuple.of(1, Arbitraries.integers()),
                Tuple.of(1, Arbitraries.of(true, false)),
                Tuple.of(1, JsonArbitraries.value(2).map(node -> MAPPER.convertValue(node, Object.class))));
        Arbitrary<Object> absentNullOrValue = Arbitraries.frequencyOf(
                Tuple.of(1, Arbitraries.just(ABSENT)),
                Tuple.of(1, Arbitraries.just((Object) null)),
                Tuple.of(6, value));
        Arbitrary<Map<String, Object>> others = Arbitraries.maps(JsonArbitraries.text(), value).ofMaxSize(2);
        return Combinators.combine(absentNullOrValue.list().ofSize(KNOWN_CONTEXT_FIELDS.size()), others)
                .as((known, rest) -> {
                    Map<String, Object> context = new LinkedHashMap<>(rest);
                    for (int i = 0; i < known.size(); i++) {
                        if (known.get(i) != ABSENT) {
                            context.put(KNOWN_CONTEXT_FIELDS.get(i), known.get(i));
                        }
                    }
                    return context;
                });
    }
}
