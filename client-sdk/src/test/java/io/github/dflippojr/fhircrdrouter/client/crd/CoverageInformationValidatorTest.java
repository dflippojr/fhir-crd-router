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
              {"url":"questionnaire","valueCanonical":"http://example.org/Questionnaire/q1"},
              {"url":"date","valueDate":"2026-09-15"},
              {"url":"coverage-assertion-id","valueString":"assert-1"},
              {"url":"expiry-date","valueDate":"2026-12"}
            ]}""";

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

    @Test
    void reasonCodingFromValueSetNeedsNoText() {
        ObjectNode ext = conformant();
        replace("reason", sub("reason", "valueCodeableConcept", MAPPER.createObjectNode().set("coding",
                MAPPER.createArrayNode().add(MAPPER.createObjectNode()
                        .put("system", "http://hl7.org/fhir/us/davinci-crd/CodeSystem/temp")
                        .put("code", "gold-card"))))).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    @Test
    void unknownSubExtensionsAreAllowedBecauseSlicingIsOpen() {
        ObjectNode ext = conformant();
        add(sub("http://example.org/payer-note", "valueString", "hi")).accept(ext);
        assertEquals(List.of(), CoverageInformationValidator.validate(ext));
    }

    @Test
    void preTwoIdentifierIsAWarningNotAnError() {
        ObjectNode ext = conformant();
        replace("coverage-assertion-id", sub("identifier", "valueString", "id-1")).accept(ext);

        assertEquals(List.of(new Violation(Severity.WARNING, "extension[identifier]",
                "identifier is the pre-2.x name for coverage-assertion-id; CRD 2.2.1 requires the url "
                        + "coverage-assertion-id")), CoverageInformationValidator.validate(ext));
    }

    /**
     * The reference implementation's response: besides the identifier warning, it omits {@code covered}
     * and {@code date}, both 1..1 in the 2.2.1 StructureDefinition. Its {@code coverageInfo}
     * sub-extension is allowed by the open slicing.
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
                        new Violation(Severity.WARNING, "extension[identifier]",
                                "identifier is the pre-2.x name for coverage-assertion-id; CRD 2.2.1 requires the "
                                        + "url coverage-assertion-id")),
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
}
