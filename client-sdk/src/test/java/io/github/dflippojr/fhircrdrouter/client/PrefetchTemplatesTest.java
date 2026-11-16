package io.github.dflippojr.fhircrdrouter.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.dflippojr.fhircrdrouter.client.PrefetchTemplates.Expansion;
import io.github.dflippojr.fhircrdrouter.client.crd.CrdHookContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PrefetchTemplatesTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final JsonNode BUNDLE = MAPPER.createObjectNode()
            .put("resourceType", "Bundle").put("type", "collection");
    private static final String COVERAGE = "Coverage?patient={{context.patientId}}&status=active";

    private static CdsHookRequest orderSign(String userId, String patientId, String encounterId) {
        return CdsHookRequest.of(new CrdHookContext.OrderSign(userId, patientId, encounterId, BUNDLE), null);
    }

    private static CdsHookRequest untyped(Map<String, Object> context) {
        return new CdsHookRequest("order-sign", "hook-1", context, null);
    }

    @Test
    void expandsPatientIdForOrderSign() {
        Expansion expansion = PrefetchTemplates.expand(Map.of("coverage", COVERAGE),
                orderSign("Practitioner/prac-1", "pat-1", null));

        assertEquals(Map.of("coverage", "Coverage?patient=pat-1&status=active"), expansion.queries());
        assertTrue(expansion.unresolved().isEmpty());
    }

    @ParameterizedTest
    @CsvSource({
            "userPractitionerId, Practitioner/u-1",
            "userPractitionerRoleId, PractitionerRole/u-1",
            "userPatientId, Patient/u-1",
            "userRelatedPersonId, RelatedPerson/u-1",
    })
    void userTokenResolvesOnlyForMatchingUserIdType(String token, String userId) {
        Map<String, String> templates = new LinkedHashMap<>();
        for (String other : List.of("userPractitionerId", "userPractitionerRoleId", "userPatientId",
                "userRelatedPersonId")) {
            templates.put(other, "X?id={{" + other + "}}");
        }

        Expansion expansion = PrefetchTemplates.expand(templates, untyped(Map.of("userId", userId)));

        assertEquals(Map.of(token, "X?id=u-1"), expansion.queries());
        assertEquals(3, expansion.unresolved().size());
        expansion.unresolved().values().forEach(reason -> assertTrue(reason.contains("context.userId"), reason));
    }

    @Test
    void expandsEveryTokenInTemplate() {
        Expansion expansion = PrefetchTemplates.expand(
                Map.of("roles", "PractitionerRole?practitioner={{userPractitionerId}}&patient={{context.patientId}}"),
                orderSign("Practitioner/prac-1", "pat-1", null));

        assertEquals("PractitionerRole?practitioner=prac-1&patient=pat-1", expansion.queries().get("roles"));
    }

    @Test
    void unresolvableTemplatesAreReportedWithoutThrowing() {
        Map<String, String> templates = new LinkedHashMap<>();
        templates.put("encounter", "Encounter/{{context.encounterId}}");
        templates.put("orders", "Bundle?x={{context.draftOrders}}");
        templates.put("deviceRequestBundle",
                "DeviceRequest?_id={{context.draftOrders.DeviceRequest.id}}&_include=DeviceRequest:patient");
        templates.put("unknown", "Patient/{{patientId}}");
        templates.put("fhirpath", "Observation?date=gt{{today() - 90 days}}");
        templates.put("unterminated", "Coverage?patient={{context.patientId");
        templates.put("noUser", "Practitioner/{{userPractitionerId}}");
        templates.put("nullTemplate", null);

        Expansion expansion = PrefetchTemplates.expand(templates,
                CdsHookRequest.of(new CrdHookContext.OrderDispatch("pat-1", List.of("ServiceRequest/sr-1"),
                        null, null), null));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        Map<String, String> reasons = expansion.unresolved();
        assertEquals(List.copyOf(templates.keySet()), List.copyOf(reasons.keySet()));
        assertEquals("context.encounterId is absent", reasons.get("encounter"));
        assertEquals("context.draftOrders is absent", reasons.get("orders"));
        assertTrue(reasons.get("deviceRequestBundle").contains("nested path"));
        assertTrue(reasons.get("unknown").contains("unsupported token"));
        assertTrue(reasons.get("fhirpath").contains("unsupported token"));
        assertEquals("unterminated {{", reasons.get("unterminated"));
        assertEquals("context.userId is absent", reasons.get("noUser"));
        assertEquals("template is null", reasons.get("nullTemplate"));
    }

    /** A first segment that is no field name is not a nested path either, so it never expands (#155, #160, #201). */
    @ParameterizedTest
    @ValueSource(strings = {"context..patientId", "context.1x.y"})
    void contextTokenWithInvalidFirstSegmentIsUnsupported(String token) {
        Map<String, String> templates = new LinkedHashMap<>();
        templates.put("bad", "Coverage?patient={{" + token + "}}&status=active");
        templates.put("coverage", COVERAGE);

        Expansion expansion = PrefetchTemplates.expand(templates, orderSign("Practitioner/prac-1", "pat-1", null));

        assertEquals(Map.of("coverage", "Coverage?patient=pat-1&status=active"), expansion.queries());
        assertEquals(Map.of("bad", "unsupported token {{" + token + "}}"), expansion.unresolved());
    }

    @Test
    void nonPrimitiveContextFieldIsUnresolved() {
        Expansion expansion = PrefetchTemplates.expand(Map.of("orders", "X?q={{context.draftOrders}}"),
                orderSign("Practitioner/prac-1", "pat-1", null));

        assertEquals(Map.of("orders", "context.draftOrders is not a primitive"), expansion.unresolved());
    }

    @Test
    void percentEncodesNonIdValuesAndKeepsIds() {
        Map<String, Object> context = new HashMap<>();
        context.put("patientId", "a&b=c d");
        context.put("encounterId", "enc-1.2");
        context.put("count", 3);
        context.put("flag", true);

        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "p", "Patient?_id={{context.patientId}}",
                "e", "Encounter/{{context.encounterId}}",
                "n", "X?count={{context.count}}&flag={{context.flag}}"), untyped(context));

        assertEquals("Patient?_id=a%26b%3Dc%20d", expansion.queries().get("p"));
        assertEquals("Encounter/enc-1.2", expansion.queries().get("e"));
        assertEquals("X?count=3&flag=true", expansion.queries().get("n"));
    }

    @ParameterizedTest
    @CsvSource({".", "..", "..."})
    void dotOnlyIdsAreUnresolvedWithoutTheValueInTheReason(String dots) {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "patient", "Patient/{{context.patientId}}",
                "practitioner", "Practitioner/{{userPractitionerId}}"),
                untyped(Map.of("patientId", dots, "userId", "Practitioner/" + dots)));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals(Map.of(
                "patient", "context.patientId is not a usable id",
                "practitioner", "{{userPractitionerId}} is not a usable id"), expansion.unresolved());
        expansion.unresolved().values().forEach(reason -> {
            assertFalse(reason.contains(".."), reason);
            assertFalse(reason.contains("Practitioner/"), reason);
        });
    }

    @Test
    void dotOnlyContextUserIdIsUnresolved() {
        Expansion expansion = PrefetchTemplates.expand(Map.of("user", "{{context.userId}}"),
                untyped(Map.of("userId", ".")));

        assertEquals(Map.of("user", "context.userId is not a usable id"), expansion.unresolved());
    }

    @Test
    void emptyPatientIdLeavesPatientAndCoverageUnresolved() {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "patient", "Patient/{{context.patientId}}",
                "coverage", COVERAGE), untyped(Map.of("patientId", "")));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals(Map.of(
                "patient", "context.patientId is empty or blank",
                "coverage", "context.patientId is empty or blank"), expansion.unresolved());
    }

    @Test
    void emptyTypedEncounterIdIsUnresolved() {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "encounter", "Encounter/{{context.encounterId}}",
                "encById", "Encounter?_id={{context.encounterId}}"), orderSign("Practitioner/p1", "pat-1", ""));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals(Map.of(
                "encounter", "context.encounterId is empty or blank",
                "encById", "context.encounterId is empty or blank"), expansion.unresolved());
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "   ", "\t", " \t\n"})
    void blankIdsAreUnresolvedWithoutTheValueInTheReason(String blank) {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "patient", "Patient/{{context.patientId}}",
                "practitioner", "Practitioner/{{userPractitionerId}}"),
                untyped(Map.of("patientId", blank, "userId", "Practitioner/" + blank)));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals("context.patientId is empty or blank", expansion.unresolved().get("patient"));
        assertTrue(expansion.unresolved().get("practitioner").startsWith("{{userPractitionerId}}"),
                expansion.unresolved().toString());
        expansion.unresolved().values().forEach(reason -> assertFalse(reason.contains("Practitioner/"), reason));
    }

    @Test
    void blankUserIdIsUnresolvedForUserTokens() {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "user", "{{context.userId}}",
                "practitioner", "Practitioner/{{userPractitionerId}}"), untyped(Map.of("userId", "  ")));

        assertEquals(Map.of(
                "user", "context.userId is empty or blank",
                "practitioner", "context.userId is empty or blank"), expansion.unresolved());
    }

    /**
     * FHIR R4 search escaping (https://hl7.org/fhir/R4/search.html#escaping): {@code ,} is OR and {@code |} and
     * {@code $} are separators, and a server URL-decodes before it parses them, so {@code %2C} still acts as OR
     * (#160). In a query value they are backslash-escaped, and the backslash itself too, before percent-encoding.
     */
    @ParameterizedTest
    @CsvSource(delimiter = ';', quoteCharacter = '"', value = {
            "pat-1,pat-2; pat-1%5C%2Cpat-2",
            ",; %5C%2C",
            "http://loinc.org|1234-5; http%3A%2F%2Floinc.org%5C%7C1234-5",
            "a$b; a%5C%24b",
            "a\\b; a%5C%5Cb",
            "a\\,b; a%5C%5C%5C%2Cb",
    })
    void searchSyntaxInAQueryValueIsBackslashEscaped(String value, String expected) {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "coverage", COVERAGE,
                "identified", "Patient?identifier={{context.patientId}}"), untyped(Map.of("patientId", value)));

        assertEquals(Map.of(
                "coverage", "Coverage?patient=" + expected + "&status=active",
                "identified", "Patient?identifier=" + expected), expansion.queries());
    }

    @Test
    void searchSyntaxBeforeTheQueryStringIsOnlyPercentEncoded() {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "patient", "Patient/{{context.patientId}}",
                "both", "Patient/{{context.patientId}}/_history?_id={{context.patientId}}"),
                untyped(Map.of("patientId", "a,b|c$d\\e")));

        assertEquals("Patient/a%2Cb%7Cc%24d%5Ce", expansion.queries().get("patient"));
        assertEquals("Patient/a%2Cb%7Cc%24d%5Ce/_history?_id=a%5C%2Cb%5C%7Cc%5C%24d%5C%5Ce",
                expansion.queries().get("both"));
    }

    /** Review advisory 3 on #158: {@code practitioner=Practitioner%2F} is a reference with no id (#160). */
    @ParameterizedTest
    @ValueSource(strings = {"Practitioner/", "Practitioner/ ", "Practitioner/\u00A0", "Patient/.", "Patient/.."})
    void aContextReferenceWithATypePrefixAndNoIdIsUnresolved(String reference) {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "roles", "PractitionerRole?practitioner={{context.userId}}",
                "patient", "Patient/{{context.patientId}}"),
                untyped(Map.of("userId", reference, "patientId", reference)));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals(Map.of(
                "roles", "context.userId has no usable id after its type prefix",
                "patient", "context.patientId has no usable id after its type prefix"), expansion.unresolved());
    }

    @Test
    void aContextReferenceWithAnIdStillExpands() {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "roles", "PractitionerRole?practitioner={{context.userId}}"),
                untyped(Map.of("userId", "Practitioner/prac-1")));

        assertEquals(Map.of("roles", "PractitionerRole?practitioner=Practitioner%2Fprac-1"), expansion.queries());
    }

    /**
     * Review advisory 2 on #158: {@link String#isBlank} misses no-break and zero-width spaces, so a value of only
     * those is a blank id too (#160).
     */
    @ParameterizedTest
    @ValueSource(strings = {"\u00A0", "\u2007", "\u202F", "\u200B", "\uFEFF", "\u2028", "\u3000\u00A0 \u200B"})
    void unicodeBlanksAreUnresolved(String blank) {
        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "coverage", COVERAGE,
                "practitioner", "Practitioner/{{userPractitionerId}}"),
                untyped(Map.of("patientId", blank, "userId", "Practitioner/" + blank)));

        assertTrue(expansion.queries().isEmpty(), expansion.queries().toString());
        assertEquals(Map.of(
                "coverage", "context.patientId is empty or blank",
                "practitioner", "{{userPractitionerId}} needs a non-blank id in context.userId"),
                expansion.unresolved());
    }

    @Test
    void visibleTextAroundUnicodeSpacesStillExpands() {
        Expansion expansion = PrefetchTemplates.expand(Map.of("coverage", COVERAGE),
                untyped(Map.of("patientId", "\u00A0a\u200B")));

        assertEquals(Map.of("coverage", "Coverage?patient=%C2%A0a%E2%80%8B&status=active"), expansion.queries());
    }

    @Test
    void idsWithDotsAmongOtherCharactersExpandVerbatimAndPathsArePercentEncoded() {
        String sixtyFour = "a".repeat(32) + "." + "b-".repeat(15) + "9";
        Map<String, Object> context = new HashMap<>();
        context.put("patientId", "a..b");
        context.put("encounterId", "a.b");
        context.put("dash", "-");
        context.put("long", sixtyFour);
        context.put("up", "../..");
        context.put("userId", "Practitioner/../x");

        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "p", "Patient/{{context.patientId}}",
                "e", "Encounter/{{context.encounterId}}",
                "d", "X/{{context.dash}}",
                "l", "X/{{context.long}}",
                "u", "Patient/{{context.up}}",
                "r", "Practitioner/{{userPractitionerId}}"), untyped(context));

        assertEquals(64, sixtyFour.length());
        assertTrue(expansion.unresolved().isEmpty(), expansion.unresolved().toString());
        assertEquals("Patient/a..b", expansion.queries().get("p"));
        assertEquals("Encounter/a.b", expansion.queries().get("e"));
        assertEquals("X/-", expansion.queries().get("d"));
        assertEquals("X/" + sixtyFour, expansion.queries().get("l"));
        assertEquals("Patient/..%2F..", expansion.queries().get("u"));
        assertEquals("Practitioner/..%2Fx", expansion.queries().get("r"));
    }

    @Test
    void mapsAreImmutableAndKeepInputOrder() {
        Map<String, String> templates = new LinkedHashMap<>();
        for (String key : List.of("z", "a", "m", "b", "y", "c")) {
            templates.put(key, key.compareTo("m") < 0 ? COVERAGE : "Encounter/{{context.encounterId}}");
        }

        Expansion expansion = PrefetchTemplates.expand(templates, orderSign("Practitioner/prac-1", "pat-1", null));

        assertEquals(List.of("a", "b", "c"), List.copyOf(expansion.queries().keySet()));
        assertEquals(List.of("z", "m", "y"), List.copyOf(expansion.unresolved().keySet()));
        assertThrows(UnsupportedOperationException.class, () -> expansion.queries().put("x", "y"));
        assertThrows(UnsupportedOperationException.class, () -> expansion.unresolved().clear());
    }

    @Test
    void reasonsNeverContainContextValues() {
        Map<String, Object> context = new HashMap<>();
        context.put("userId", "Patient/secret-user-7");
        context.put("patientId", Map.of("nested", "secret-mrn-9"));
        context.put("encounterId", List.of("secret-enc-3"));

        Expansion expansion = PrefetchTemplates.expand(Map.of(
                "a", "Patient/{{context.patientId}}",
                "b", "Encounter/{{context.encounterId}}",
                "c", "Practitioner/{{userPractitionerId}}",
                "d", "X/{{context.patientId.nested}}"), untyped(context));

        assertEquals(4, expansion.unresolved().size());
        expansion.unresolved().values().forEach(reason -> {
            assertFalse(reason.contains("secret"), reason);
            assertFalse(reason.contains("Patient/"), reason);
        });
    }

    @Test
    void worksForEveryTypedContext() {
        List<CrdHookContext> contexts = List.of(
                new CrdHookContext.OrderSign("Practitioner/prac-1", "pat-1", null, BUNDLE),
                new CrdHookContext.OrderSelect("Practitioner/prac-1", "pat-1", null,
                        List.of("ServiceRequest/sr-1"), BUNDLE),
                new CrdHookContext.OrderDispatch("pat-1", List.of("ServiceRequest/sr-1"), null, null),
                new CrdHookContext.AppointmentBook("Practitioner/prac-1", "pat-1", null, BUNDLE),
                new CrdHookContext.EncounterStart("Practitioner/prac-1", "pat-1", "enc-1"),
                new CrdHookContext.EncounterDischarge("Practitioner/prac-1", "pat-1", "enc-1"));

        for (CrdHookContext context : contexts) {
            Expansion expansion = PrefetchTemplates.expand(Map.of("coverage", COVERAGE),
                    CdsHookRequest.of(context, null));
            assertEquals(Map.of("coverage", "Coverage?patient=pat-1&status=active"), expansion.queries(),
                    context.hook());
        }
    }

    @Test
    void templatesWithoutTokensPassThroughAndNullArgumentsThrow() {
        CdsHookRequest request = orderSign("Practitioner/prac-1", "pat-1", null);

        assertEquals(Map.of("all", "Coverage?status=active"),
                PrefetchTemplates.expand(Map.of("all", "Coverage?status=active"), request).queries());
        assertTrue(PrefetchTemplates.expand(Map.of(), request).queries().isEmpty());
        assertThrows(NullPointerException.class, () -> PrefetchTemplates.expand(null, request));
        assertThrows(NullPointerException.class, () -> PrefetchTemplates.expand(Map.of(), null));
    }
}
