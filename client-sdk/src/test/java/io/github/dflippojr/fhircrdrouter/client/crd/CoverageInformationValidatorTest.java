package io.github.dflippojr.fhircrdrouter.client.crd;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.dflippojr.fhircrdrouter.client.CdsHookResponse;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformationValidator.Severity;
import io.github.dflippojr.fhircrdrouter.client.crd.CoverageInformationValidator.Violation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class CoverageInformationValidatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Synthetic, conformant CRD 2.2.1 coverage-information. */
    private static final String CONFORMANT = """
            {"url":"http://hl7.org/fhir/us/davinci-crd/StructureDefinition/ext-coverage-information","extension":[
              {"url":"coverage","valueReference":{"reference":"Coverage/cov1"}},
              {"url":"covered","valueCode":"covered"},
              {"url":"pa-needed","valueCode":"auth-needed"},
              {"url":"doc-needed","valueCode":"clinical"},
              {"url":"doc-purpose","valueCode":"withpa"},
              {"url":"reason","valueCodeableConcept":{"text":"Prior authorization requires clinical notes"}},
              {"url":"detail","extension":[
                {"url":"category","valueCode":"cat-limitation"},
                {"url":"code","valueCodeableConcept":{"text":"Visits per year"}},
                {"url":"value","valueString":"12"}
              ]},
              {"url":"questionnaire","valueCanonical":"http://example.org/Questionnaire/q1"},
              {"url":"date","valueDate":"2026-09-15"},
              {"url":"coverage-assertion-id","valueString":"assert-1"},
              {"url":"expiry-date","valueDate":"2026-12"}
            ]}""";

    private static final String DETAIL = "extension[detail][0].extension";

    private static final String IDENTIFIER_WARNING = "identifier is the pre-2.x name for coverage-assertion-id; "
            + "CRD 2.2.1 requires the url coverage-assertion-id";
    private static final String COVERAGE_INFO_WARNING = "coverageInfo is a reference implementation sub-extension "
            + "that CRD 2.2.1 does not define";

    @Test
    void conformantExtensionHasNoViolations() {
        assertEquals(List.of(), CoverageInformationValidator.validate(conformant()));
    }

    @Test
    void minimalConformantExtensionHasNoViolations() {
        assertEquals(List.of(), CoverageInformationValidator.validate(extension(
                sub("coverage", "valueReference", MAPPER.createObjectNode().put("reference", "Coverage/c")),
                sub("covered", "valueCode", "not-covered"),
                sub("date", "valueDate", "2026"),
                sub("coverage-assertion-id", "valueString", "a"))));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("brokenRules")
    void eachBrokenRuleReportsPathAndSeverity(String rule, Consumer<ObjectNode> breakIt, String path,
                                              String messageFragment) {
        ObjectNode ext = conformant();
        breakIt.accept(ext);

        List<Violation> violations = CoverageInformationValidator.validate(ext);

        assertEquals(1, violations.size(), () -> rule + ": " + violations);
        Violation v = violations.get(0);
        assertEquals(Severity.ERROR, v.severity());
        assertEquals(path, v.path());
        assertTrue(v.message().contains(messageFragment), v.message());
    }

    static Stream<Arguments> brokenRules() {
        return Stream.of(
                arguments("wrong url", set(e -> e.put("url", "http://example.org/other")), "url", "url must be"),
                arguments("value[x] on complex extension", set(e -> e.put("valueString", "x")),
                        "valueString", "complex extension"),
                arguments("coverage required", remove("coverage"), "extension[coverage]", "coverage is required"),
                arguments("covered required", remove("covered"), "extension[covered]", "covered is required"),
                arguments("date required", remove("date"), "extension[date]", "date is required"),
                arguments("coverage-assertion-id required", remove("coverage-assertion-id"),
                        "extension[coverage-assertion-id]", "coverage-assertion-id is required"),
                arguments("covered max 1", add(sub("covered", "valueCode", "covered")),
                        "extension[covered]", "at most once"),
                arguments("pa-needed max 1", add(sub("pa-needed", "valueCode", "auth-needed")),
                        "extension[pa-needed]", "at most once"),
                arguments("expiry-date max 1", add(sub("expiry-date", "valueDate", "2027")),
                        "extension[expiry-date]", "at most once"),
                arguments("covered value type", replace("covered", sub("covered", "valueCoding",
                        MAPPER.createObjectNode().put("code", "covered"))),
                        "extension[covered]", "must have a valueCode, found valueCoding"),
                arguments("covered code", replace("covered", sub("covered", "valueCode", "yes")),
                        "extension[covered]", "code 'yes' is not one of"),
                arguments("pa-needed code", replace("pa-needed", sub("pa-needed", "valueCode", "noauth")),
                        "extension[pa-needed]", "code 'noauth' is not one of"),
                arguments("doc-needed code", replace("doc-needed", sub("doc-needed", "valueCode", "billing")),
                        "extension[doc-needed]", "code 'billing'"),
                arguments("info-needed code", add(sub("info-needed", "valueCode", "payer")),
                        "extension[info-needed]", "code 'payer'"),
                arguments("doc-purpose code", replace("doc-purpose", sub("doc-purpose", "valueCode", "later")),
                        "extension[doc-purpose]", "code 'later'"),
                arguments("date format", replace("date", sub("date", "valueDate", "09/15/2026")),
                        "extension[date]", "not a FHIR date"),
                arguments("date is a dateTime", replace("date", sub("date", "valueDate", "2026-09-15T10:00:00Z")),
                        "extension[date]", "not a FHIR date"),
                arguments("date not on calendar", replace("date", sub("date", "valueDate", "2026-02-30")),
                        "extension[date]", "not a FHIR date"),
                arguments("expiry-date format", replace("expiry-date", sub("expiry-date", "valueDate", "2026-13")),
                        "extension[expiry-date]", "not a FHIR date"),
                arguments("coverage reference target", replace("coverage", sub("coverage", "valueReference",
                        MAPPER.createObjectNode().put("reference", "Patient/p1"))),
                        "extension[coverage]", "must reference a Coverage"),
                arguments("coverage reference empty", replace("coverage", sub("coverage", "valueReference",
                        MAPPER.createObjectNode().put("display", "Plan A"))),
                        "extension[coverage]", "no reference or identifier"),
                arguments("coverage reference type", replace("coverage", sub("coverage", "valueReference",
                        MAPPER.createObjectNode().put("type", "Patient"))),
                        "extension[coverage]", "got type Patient"),
                arguments("coverage-assertion-id value type", replace("coverage-assertion-id",
                        sub("coverage-assertion-id", "valueIdentifier", MAPPER.createObjectNode().put("value", "a"))),
                        "extension[coverage-assertion-id]", "must have a valueString"),
                arguments("detail category required", inDetail(remove("category")),
                        DETAIL + "[category]", "detail category is required"),
                arguments("detail code required", inDetail(remove("code")),
                        DETAIL + "[code]", "detail code is required"),
                arguments("detail value required", inDetail(remove("value")),
                        DETAIL + "[value]", "detail value is required"),
                arguments("detail code max 1", inDetail(add(sub("code", "valueCodeableConcept",
                        MAPPER.createObjectNode().put("text", "Visits per month")))),
                        DETAIL + "[code]", "detail code may appear at most once, found 2"),
                arguments("detail qualification max 1", inDetail(add(sub("qualification", "valueString", "a"),
                        sub("qualification", "valueString", "b"))),
                        DETAIL + "[qualification]", "detail qualification may appear at most once, found 2"),
                arguments("detail category code", inDetail(replace("category", sub("category", "valueCode",
                        "cat-visits"))), DETAIL + "[category]",
                        "detail category code 'cat-visits' is not one of cat-decisional, cat-limitation, cat-other"),
                arguments("detail category value type", inDetail(replace("category", sub("category", "valueCoding",
                        MAPPER.createObjectNode().put("code", "cat-limitation")))),
                        DETAIL + "[category]", "detail category must have a valueCode, found valueCoding"),
                arguments("detail code value type", inDetail(replace("code", sub("code", "valueString", "visits"))),
                        DETAIL + "[code]", "detail code must have a valueCodeableConcept, found valueString"),
                arguments("detail value value type", inDetail(replace("value",
                        sub("value", "valueInteger", MAPPER.getNodeFactory().numberNode(12)))),
                        DETAIL + "[value]", "detail value must have a valueBoolean, valueString, valueUrl, "
                                + "valuePeriod or valueQuantity, found valueInteger"),
                arguments("detail qualification value type", inDetail(add(sub("qualification", "valueCode", "x"))),
                        DETAIL + "[qualification]", "detail qualification must have a valueString, found valueCode"),
                arguments("crd-ci-q1", remove("doc-needed"), "extension[questionnaire]", "crd-ci-q1"),
                arguments("crd-ci-q2", replace("covered", sub("covered", "valueCode", "not-covered")),
                        "extension[pa-needed]", "crd-ci-q2"),
                arguments("crd-ci-q3", replace("covered", sub("covered", "valueCode", "conditional")),
                        "extension[info-needed]", "crd-ci-q3"),
                arguments("crd-ci-q4", replace("pa-needed", sub("pa-needed", "valueCode", "no-auth")),
                        "extension[doc-purpose]", "crd-ci-q4"),
                arguments("crd-ci-q5 missing id", replace("pa-needed", sub("pa-needed", "valueCode", "satisfied"))
                        .andThen(replace("doc-purpose", sub("doc-purpose", "valueCode", "withclaim"))),
                        "extension[satisfied-pa-id]", "required when pa-needed is satisfied (crd-ci-q5)"),
                arguments("crd-ci-q5 unexpected id", add(sub("satisfied-pa-id", "valueString", "pa-1")),
                        "extension[satisfied-pa-id]", "only allowed when pa-needed is satisfied (crd-ci-q5)"),
                arguments("crd-ci-q6", add(sub("info-needed", "valueCode", "OTH"))
                        .andThen(remove("reason")).andThen(remove("doc-purpose")),
                        "extension[reason]", "crd-ci-q6"),
                arguments("crd-ci-q7", replace("reason", sub("reason", "valueCodeableConcept",
                        MAPPER.createObjectNode().set("coding", MAPPER.createArrayNode().add(
                                MAPPER.createObjectNode().put("system", "http://example.org").put("code", "x"))))),
                        "extension[reason]", "crd-ci-q7"),
                arguments("crd-ci-q8", remove("reason"), "extension[reason]", "crd-ci-q8"),
                arguments("crd-ci-q9", replace("doc-needed", sub("doc-needed", "valueCode", "indeterminate"))
                        .andThen(remove("reason")).andThen(remove("doc-purpose")),
                        "extension[reason]", "crd-ci-q9"));
    }

    /** #126: detail's value is boolean, string, url, Period or Quantity (CRD 2.2.1 ext-coverage-information). */
    @ParameterizedTest(name = "{0}")
    @MethodSource("detailValues")
    void eachAllowedDetailValueTypeConforms(String valueType, JsonNode value) {
        ObjectNode ext = conformant();
        inDetail(replace("value", sub("value", valueType, value))
                .andThen(add(sub("qualification", "valueString", "Per calendar year")))).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    static Stream<Arguments> detailValues() {
        return Stream.of(
                arguments("valueBoolean", MAPPER.getNodeFactory().booleanNode(true)),
                arguments("valueString", MAPPER.getNodeFactory().textNode("12")),
                arguments("valueUrl", MAPPER.getNodeFactory().textNode("http://example.org/limits")),
                arguments("valuePeriod", MAPPER.createObjectNode().put("start", "2026-01-01")),
                arguments("valueQuantity", MAPPER.createObjectNode().put("value", 12).put("unit", "visits")));
    }

    /** #126: each detail is checked on its own, and the path says which one. */
    @Test
    void secondDetailIsCheckedAndNamedByIndex() {
        ObjectNode ext = conformant();
        add(MAPPER.createObjectNode().put("url", "detail")).accept(ext);

        assertEquals(List.of(
                        new Violation(Severity.ERROR, "extension[detail][1].extension[category]",
                                "detail category is required"),
                        new Violation(Severity.ERROR, "extension[detail][1].extension[code]",
                                "detail code is required"),
                        new Violation(Severity.ERROR, "extension[detail][1].extension[value]",
                                "detail value is required")),
                CoverageInformationValidator.validate(ext));
    }

    @Test
    void reasonCodingFromValueSetNeedsNoText() {
        ObjectNode ext = conformant();
        replace("reason", sub("reason", "valueCodeableConcept", MAPPER.createObjectNode().set("coding",
                MAPPER.createArrayNode().add(MAPPER.createObjectNode()
                        .put("system", "http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp")
                        .put("code", "gold-card"))))).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    /** #200: a sub-extension with no value[x] at all names the type it needs and nothing it found. */
    @Test
    void subExtensionWithNoValueNamesTheMissingType() {
        ObjectNode ext = conformant();
        replace("coverage", MAPPER.createObjectNode().put("url", "coverage")).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[coverage]",
                "coverage must have a valueReference")), CoverageInformationValidator.validate(ext));
    }

    /** #200: FHIR R4 allows a logical Reference, by identifier, with or without its type. */
    @ParameterizedTest(name = "{0}")
    @MethodSource("coverageByIdentifier")
    void coverageByIdentifierConforms(String shape, ObjectNode reference) {
        ObjectNode ext = conformant();
        replace("coverage", sub("coverage", "valueReference", reference)).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    static Stream<Arguments> coverageByIdentifier() {
        return Stream.of(
                arguments("identifier only", coverageIdentifier(MAPPER.createObjectNode())),
                arguments("type Coverage and identifier", coverageIdentifier(
                        MAPPER.createObjectNode().put("type", "Coverage"))));
    }

    /** #200: a type alone does not say which Coverage. */
    @Test
    void coverageWithTypeOnlyIsAnError() {
        ObjectNode ext = conformant();
        replace("coverage", sub("coverage", "valueReference",
                MAPPER.createObjectNode().put("type", "Coverage"))).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[coverage]",
                "coverage valueReference has no reference or identifier")), CoverageInformationValidator.validate(ext));
    }

    /** #200: crd-ci-q7 is met by text, whatever the coding's system. */
    @Test
    void reasonWithForeignCodingAndTextConforms() {
        ObjectNode ext = conformant();
        ObjectNode concept = reasonCoding("http://example.org/reasons", "x");
        concept.put("text", "Payer-specific reason");
        replace("reason", sub("reason", "valueCodeableConcept", concept)).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    /** #200: a coverageAssertionReasons system with a code outside the value set still needs text. */
    @Test
    void reasonCodeOutsideValueSetWithoutTextBreaksQ7() {
        ObjectNode ext = conformant();
        replace("reason", sub("reason", "valueCodeableConcept",
                reasonCoding("http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp", "zzz"))).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[reason]",
                        "reason needs text when its coding is not from the coverageAssertionReasons value set "
                                + "(crd-ci-q7)")),
                CoverageInformationValidator.validate(ext));
    }

    /** #200: a reason of the wrong type gets the type error only; crd-ci-q7 does not fire as well. */
    @Test
    void reasonAsStringIsATypeErrorNotQ7() {
        ObjectNode ext = conformant();
        replace("reason", sub("reason", "valueString", "Clinical notes")).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[reason]",
                        "reason must have a valueCodeableConcept, found valueString")),
                CoverageInformationValidator.validate(ext));
    }

    /** #200: a non-text valueCode is reported against the value set by its text form. */
    @Test
    void numericValueCodeIsNotInTheValueSet() {
        ObjectNode ext = conformant();
        replace("doc-needed", sub("doc-needed", "valueCode", MAPPER.getNodeFactory().numberNode(5))).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[doc-needed]",
                        "doc-needed code '5' is not one of admin, clinical, conditional, indeterminate, patient")),
                CoverageInformationValidator.validate(ext));
    }

    @Test
    void unknownAbsoluteUrlIsAllowedBecauseSlicingIsOpen() {
        ObjectNode ext = conformant();
        add(sub("http://example.org/payer-note", "valueString", "hi"),
                sub("urn:oid:2.16.840.1.113883", "valueString", "hi")).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    /** #125: open slicing admits absolute urls only; a relative url must be one the profile defines. */
    @Test
    void unknownRelativeUrlIsAnError() {
        ObjectNode ext = conformant();
        add(sub("note", "valueString", "x")).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[note]",
                "note is not a sub-extension of ext-coverage-information; CRD 2.2.1 allows other "
                        + "sub-extensions only with an absolute url")), CoverageInformationValidator.validate(ext));
    }

    @Test
    void subExtensionWithoutUrlIsAnError() {
        ObjectNode ext = conformant();
        add(MAPPER.createObjectNode().put("valueString", "x")).accept(ext);

        assertEquals(List.of(new Violation(Severity.ERROR, "extension[]", "a sub-extension has no url")),
                CoverageInformationValidator.validate(ext));
    }

    /** #125: the reference implementation's coverageInfo is warned about, like its legacy identifier. */
    @Test
    void referenceImplementationCoverageInfoIsAWarningNotAnError() {
        ObjectNode ext = conformant();
        add(sub("coverageInfo", "valueCoding", MAPPER.createObjectNode().put("code", "clinical"))).accept(ext);

        assertEquals(List.of(new Violation(Severity.WARNING, "extension[coverageInfo]", COVERAGE_INFO_WARNING)),
                CoverageInformationValidator.validate(ext));
    }

    @Test
    void preTwoIdentifierNextToCoverageAssertionIdIsAWarning() {
        ObjectNode ext = conformant();
        add(sub("identifier", "valueString", "id-1")).accept(ext);

        assertEquals(List.of(new Violation(Severity.WARNING, "extension[identifier]", IDENTIFIER_WARNING)),
                CoverageInformationValidator.validate(ext));
    }

    @Test
    void preTwoIdentifierIsAWarningNotAnError() {
        ObjectNode ext = conformant();
        replace("coverage-assertion-id", sub("identifier", "valueString", "id-1")).accept(ext);

        assertEquals(List.of(new Violation(Severity.WARNING, "extension[identifier]", IDENTIFIER_WARNING)),
                CoverageInformationValidator.validate(ext));
    }

    /**
     * The reference implementation's response: it omits {@code covered} and {@code date}, both 1..1 in
     * the 2.2.1 StructureDefinition, and its {@code coverageInfo} and {@code identifier} sub-extensions,
     * which the profile does not define, are warnings rather than errors.
     */
    @Test
    void referenceImplementationFixture() throws Exception {
        JsonNode raw;
        try (InputStream in = getClass().getResourceAsStream("/crd-ri/order-sign-hospital-bed-response.json")) {
            raw = MAPPER.readTree(in);
        }
        List<CoverageInformation> infos = new CdsHookResponse(List.of(), List.of(), raw).coverageInformation();
        assertEquals(1, infos.size());

        assertEquals(List.of(
                        new Violation(Severity.ERROR, "extension[covered]", "covered is required"),
                        new Violation(Severity.ERROR, "extension[date]", "date is required"),
                        new Violation(Severity.WARNING, "extension[coverageInfo]", COVERAGE_INFO_WARNING),
                        new Violation(Severity.WARNING, "extension[identifier]", IDENTIFIER_WARNING)),
                CoverageInformationValidator.validate(infos.get(0)));
    }

    @Test
    void notAnObject() {
        List<Violation> violations = CoverageInformationValidator.validate(MAPPER.createArrayNode());
        assertEquals(List.of(new Violation(Severity.ERROR, "extension", "coverage-information must be a JSON object")),
                violations);
        assertEquals(violations, CoverageInformationValidator.validate((JsonNode) null));
    }

    @Test
    void noSubExtensions() {
        ObjectNode ext = conformant();
        ext.remove("extension");
        List<Violation> violations = CoverageInformationValidator.validate(ext);
        assertEquals(new Violation(Severity.ERROR, "extension", "coverage-information has no sub-extensions"),
                violations.get(0));
        assertEquals(5, violations.size(), violations::toString);
    }

    @Test
    void violationFieldsAreRequired() {
        assertThrows(NullPointerException.class, () -> new Violation(null, "p", "m"));
        assertThrows(NullPointerException.class,
                () -> CoverageInformationValidator.validate((CoverageInformation) null));
    }

    private static ObjectNode conformant() {
        try {
            return (ObjectNode) MAPPER.readTree(CONFORMANT);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static ObjectNode extension(ObjectNode... subs) {
        ObjectNode ext = MAPPER.createObjectNode().put("url", CoverageInformation.EXTENSION_URL);
        ext.putArray("extension").addAll(List.of(subs));
        return ext;
    }

    private static ObjectNode sub(String url, String valueType, String value) {
        return MAPPER.createObjectNode().put("url", url).put(valueType, value);
    }

    private static ObjectNode sub(String url, String valueType, JsonNode value) {
        ObjectNode sub = MAPPER.createObjectNode().put("url", url);
        sub.set(valueType, value);
        return sub;
    }

    private static ObjectNode coverageIdentifier(ObjectNode reference) {
        reference.putObject("identifier").put("system", "http://example.org/member-id").put("value", "M123");
        return reference;
    }

    private static ObjectNode reasonCoding(String system, String code) {
        ObjectNode concept = MAPPER.createObjectNode();
        concept.putArray("coding").addObject().put("system", system).put("code", code);
        return concept;
    }

    private static Consumer<ObjectNode> set(Consumer<ObjectNode> change) {
        return change;
    }

    private static Consumer<ObjectNode> remove(String url) {
        return ext -> {
            ArrayNode subs = (ArrayNode) ext.get("extension");
            for (int i = subs.size() - 1; i >= 0; i--) {
                if (url.equals(subs.get(i).path("url").asText())) {
                    subs.remove(i);
                }
            }
        };
    }

    private static Consumer<ObjectNode> add(ObjectNode... subs) {
        return ext -> ((ArrayNode) ext.get("extension")).addAll(List.of(subs));
    }

    private static Consumer<ObjectNode> replace(String url, ObjectNode... subs) {
        return remove(url).andThen(add(subs));
    }

    /** Applies a change to the first detail's own sub-extensions. */
    private static Consumer<ObjectNode> inDetail(Consumer<ObjectNode> change) {
        return ext -> {
            for (JsonNode sub : ext.get("extension")) {
                if ("detail".equals(sub.path("url").asText())) {
                    change.accept((ObjectNode) sub);
                    return;
                }
            }
        };
    }
}
